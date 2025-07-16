#!/usr/bin/env python3
"""
IOC Extractor - Resilient Email Analysis Tool with Restart Capability
Extract Indicators of Compromise from email data with checkpoint/resume and job batching.
"""

import re
import json
import logging
import ipaddress
import os
import time
import hashlib
import sqlite3
from typing import Dict, List, Optional, Union, Any, Tuple
from urllib.parse import urlparse, unquote
from html import unescape
from dataclasses import dataclass, asdict
from email.utils import parseaddr
from datetime import datetime
from pathlib import Path
import sys
import pickle
import threading
from contextlib import contextmanager
from queue import Queue, Empty
import signal
from email import policy
from email.parser import BytesParser
from elasticsearch import Elasticsearch
import json
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('ioc_extractor.log')
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class IOCResult:
    """Data class for IOC extraction results"""
    filename: str
    email_hash: str
    sender_email: Optional[str] = None
    sender_ip: Optional[str] = None
    recipient_email: Optional[str] = None
    recipient_ip: Optional[str] = None
    subject: Optional[str] = None
    links: List[str] = None
    domains: List[str] = None
    urls_found: List[str] = None
    extraction_errors: List[str] = None
    processed_at: str = None
    processing_time_ms: int = 0

    def __post_init__(self):
        if self.links is None:
            self.links = []
        if self.domains is None:
            self.domains = []
        if self.urls_found is None:
            self.urls_found = []
        if self.extraction_errors is None:
            self.extraction_errors = []
        if self.processed_at is None:
            self.processed_at = datetime.now().isoformat()

class JobManager:
    """Manages job batching, checkpointing, and resume functionality"""
    
    def __init__(self, checkpoint_dir: str = "checkpoints", batch_size: int = 100, max_memory_mb: int = 512):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(exist_ok=True)
        self.batch_size = batch_size
        self.max_memory_mb = max_memory_mb
        self.db_path = self.checkpoint_dir / "progress.db"
        self.results_path = self.checkpoint_dir / "results.json"
        self.current_batch = 0
        self.total_batches = 0
        self.shutdown_requested = False
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self._init_database()
        logger.info(f"JobManager initialized - batch_size: {batch_size}, max_memory: {max_memory_mb}MB")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.shutdown_requested = True

    def _init_database(self):
        """Initialize SQLite database for progress tracking"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS processed_emails (
                    email_hash TEXT PRIMARY KEY,
                    filename TEXT,
                    batch_number INTEGER,
                    processed_at TEXT,
                    processing_time_ms INTEGER,
                    success BOOLEAN
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS job_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.commit()

    def get_email_hash(self, email_data: Dict[str, Any]) -> str:
        """Generate unique hash for email data"""
        # Create hash from essential email components
        hash_input = f"{email_data.get('filename', '')}{email_data.get('from', '')}{email_data.get('to', '')}{email_data.get('subject', '')}{email_data.get('body', '')}"
        return hashlib.sha256(hash_input.encode()).hexdigest()

    def is_email_processed(self, email_hash: str) -> bool:
        """Check if email has already been processed"""
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute(
                "SELECT 1 FROM processed_emails WHERE email_hash = ? AND success = 1",
                (email_hash,)
            ).fetchone()
            return result is not None

    def mark_email_processed(self, email_hash: str, filename: str, batch_number: int, 
                           processing_time_ms: int, success: bool = True):
        """Mark email as processed"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO processed_emails 
                (email_hash, filename, batch_number, processed_at, processing_time_ms, success)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (email_hash, filename, batch_number, datetime.now().isoformat(), 
                  processing_time_ms, success))
            conn.commit()

    def get_processing_stats(self) -> Dict[str, Any]:
        """Get processing statistics"""
        with sqlite3.connect(self.db_path) as conn:
            stats = conn.execute("""
                SELECT 
                    COUNT(*) as total_processed,
                    COUNT(CASE WHEN success = 1 THEN 1 END) as successful,
                    COUNT(CASE WHEN success = 0 THEN 1 END) as failed,
                    AVG(processing_time_ms) as avg_processing_time_ms,
                    MAX(batch_number) as max_batch
                FROM processed_emails
            """).fetchone()
            
            return {
                "total_processed": stats[0] or 0,
                "successful": stats[1] or 0,
                "failed": stats[2] or 0,
                "avg_processing_time_ms": stats[3] or 0,
                "max_batch_processed": stats[4] or 0
            }

    def create_batches(self, emails: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Create batches from email list, skipping already processed emails"""
        unprocessed_emails = []
        skipped_count = 0
        
        for email in emails:
            email_hash = self.get_email_hash(email)
            if not self.is_email_processed(email_hash):
                email['_hash'] = email_hash  # Store hash for later use
                unprocessed_emails.append(email)
            else:
                skipped_count += 1
        
        if skipped_count > 0:
            logger.info(f"Skipped {skipped_count} already processed emails")
        
        logger.info(f"Processing {len(unprocessed_emails)} unprocessed emails")
        
        # Create batches
        batches = []
        for i in range(0, len(unprocessed_emails), self.batch_size):
            batch = unprocessed_emails[i:i + self.batch_size]
            batches.append(batch)
        
        self.total_batches = len(batches)
        return batches

    def save_batch_results(self, batch_results: List[IOCResult], batch_number: int):
        """Save batch results incrementally"""
        # Load existing results
        existing_results = []
        if self.results_path.exists():
            try:
                with open(self.results_path, 'r', encoding='utf-8') as f:
                    existing_results = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load existing results: {e}")
        
        # Add new results
        new_results = [asdict(result) for result in batch_results]
        existing_results.extend(new_results)
        
        # Save updated results
        with open(self.results_path, 'w', encoding='utf-8') as f:
            json.dump(existing_results, f, indent=2, ensure_ascii=False)
        
        # Create backup
        backup_path = self.checkpoint_dir / f"results_batch_{batch_number}.json"
        with open(backup_path, 'w', encoding='utf-8') as f:
            json.dump(new_results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Saved batch {batch_number} results ({len(batch_results)} items)")

    def get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB"""
        import psutil
        try:
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            # Fallback if psutil not available
            return 0.0

class IOCExtractor:
    """Resilient IOC extractor with comprehensive error handling and validation"""
    
    def __init__(self):
        # Comprehensive URL regex patterns
        self.url_patterns = [
            # HTTP/HTTPS URLs
            re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            # FTP URLs
            re.compile(r'ftp://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            # Generic protocol URLs
            re.compile(r'[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            # URLs without protocol (www.example.com)
            re.compile(r'www\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*', re.IGNORECASE),
            # Domain-like patterns
            re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b', re.IGNORECASE)
        ]
        
        # HTML link extraction
        self.html_link_pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
        
        # Email validation pattern
        self.email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        
        # Domain extraction pattern
        self.domain_pattern = re.compile(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}')

    def validate_ip_address(self, ip_str: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip_str.strip())
            return True
        except ValueError:
            return False

    def validate_email(self, email_str: str) -> bool:
        """Validate email format"""
        if not email_str:
            return False
        return bool(self.email_pattern.match(email_str.strip()))

    def clean_text(self, text: str) -> str:
        """Clean and normalize text input"""
        if not text:
            return ""
        
        # Unescape HTML entities
        text = unescape(text)
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove null bytes and control characters
        text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
        
        return text.strip()

    def extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text using multiple patterns"""
        urls = set()
        
        if not text:
            return []
        
        # Clean text first
        text = self.clean_text(text)
        
        # Extract HTML links first
        html_links = self.html_link_pattern.findall(text)
        for link in html_links:
            urls.add(unquote(link))
        
        # Apply all URL patterns
        for pattern in self.url_patterns:
            matches = pattern.findall(text)
            for match in matches:
                # If match is a tuple (from capturing groups), use the first group
                if isinstance(match, tuple):
                    match_str = match[0]
                else:
                    match_str = match
                clean_match = match_str.rstrip('.,;:!?)')
                urls.add(clean_match)
        
        # Filter out obvious false positives
        filtered_urls = []
        for url in urls:
            if len(url) > 3 and not url.endswith('.'):
                filtered_urls.append(url)
        
        return sorted(list(set(filtered_urls)))

    def extract_domains_from_urls(self, urls: List[str]) -> List[str]:
        """Extract domains from URLs"""
        domains = set()
        
        for url in urls:
            try:
                # Add protocol if missing
                if not url.startswith(('http://', 'https://', 'ftp://')):
                    if url.startswith('www.'):
                        url = 'http://' + url
                    else:
                        # Check if it looks like a domain
                        if '.' in url and not url.startswith('/'):
                            url = 'http://' + url
                
                parsed = urlparse(url)
                if parsed.netloc:
                    # Clean domain
                    domain = parsed.netloc.lower()
                    # Remove port if present
                    if ':' in domain:
                        domain = domain.split(':')[0]
                    domains.add(domain)
                
            except Exception as e:
                logger.warning(f"Failed to parse URL {url}: {e}")
                # Try to extract domain with regex as fallback
                domain_match = self.domain_pattern.search(url)
                if domain_match:
                    domains.add(domain_match.group().lower())
        
        return sorted(list(domains))

    def extract_email_address(self, email_field: str) -> Optional[str]:
        """Extract email address from various formats"""
        if not email_field:
            return None
        
        # Clean the field
        email_field = self.clean_text(email_field)
        
        # Handle "Name <email@domain.com>" format
        name, email = parseaddr(email_field)
        if email and self.validate_email(email):
            return email.lower()
        
        # Direct email validation
        if self.validate_email(email_field):
            return email_field.lower()
        
        # Extract email using regex as fallback
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', email_field)
        if email_match:
            extracted_email = email_match.group()
            if self.validate_email(extracted_email):
                return extracted_email.lower()
        
        return None

    def extract_ip_address(self, ip_field: Union[str, None]) -> Optional[str]:
        """Extract and validate IP address"""
        if not ip_field:
            return None
        
        ip_str = str(ip_field).strip()
        
        # Direct validation
        if self.validate_ip_address(ip_str):
            return ip_str
        
        # Extract IP using regex
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        ip_match = ip_pattern.search(ip_str)
        if ip_match:
            extracted_ip = ip_match.group()
            if self.validate_ip_address(extracted_ip):
                return extracted_ip
        
        return None

    def extract_iocs_from_email(self, email_data: Dict[str, Any]) -> IOCResult:
        """Extract all IOCs from a single email"""
        start_time = time.time()
        email_hash = email_data.get('_hash', '')
        result = IOCResult(
            filename=email_data.get('filename', 'unknown'),
            email_hash=email_hash
        )
        
        try:
            # Extract sender email
            sender_email = self.extract_email_address(email_data.get('from'))
            if sender_email:
                result.sender_email = sender_email
            else:
                result.extraction_errors.append("Failed to extract valid sender email")
            
            # Extract sender IP
            sender_ip = self.extract_ip_address(email_data.get('sender_ip'))
            if sender_ip:
                result.sender_ip = sender_ip
            else:
                result.extraction_errors.append("Failed to extract valid sender IP")
            
            # Extract recipient email
            recipient_email = self.extract_email_address(email_data.get('to'))
            if recipient_email:
                result.recipient_email = recipient_email
            else:
                result.extraction_errors.append("Failed to extract valid recipient email")
            
            # Extract recipient IP
            recipient_ip = self.extract_ip_address(email_data.get('recipient_ip'))
            if recipient_ip:
                result.recipient_ip = recipient_ip
            else:
                result.extraction_errors.append("Failed to extract valid recipient IP")
            
            # Extract subject
            subject = email_data.get('subject')
            if subject:
                result.subject = self.clean_text(subject)
            
            # Extract URLs and domains from body
            body = email_data.get('body', '')
            if body:
                urls = self.extract_urls_from_text(body)
                result.urls_found = urls
                result.links = urls  # Links are the same as URLs in this context
                result.domains = self.extract_domains_from_urls(urls)
            
        except Exception as e:
            error_msg = f"Error processing email {result.filename}: {str(e)}"
            logger.error(error_msg)
            result.extraction_errors.append(error_msg)
        
        # Calculate processing time
        result.processing_time_ms = int((time.time() - start_time) * 1000)
        
        return result

class ResumableIOCProcessor:
    """Main processor with restart capability and job management"""
    
    def __init__(self, batch_size: int = 100, max_memory_mb: int = 512, 
                 checkpoint_dir: str = "checkpoints"):
        self.extractor = IOCExtractor()
        self.job_manager = JobManager(checkpoint_dir, batch_size, max_memory_mb)
        self.batch_size = batch_size
        self.max_memory_mb = max_memory_mb

    def process_emails(self, emails: List[Dict[str, Any]]) -> List[IOCResult]:
        """Process emails with restart capability"""
        logger.info(f"Starting IOC extraction for {len(emails)} emails")
        
        # Get initial stats
        initial_stats = self.job_manager.get_processing_stats()
        logger.info(f"Initial stats: {initial_stats}")
        
        # Create batches (automatically skips processed emails)
        batches = self.job_manager.create_batches(emails)
        
        if not batches:
            logger.info("No new emails to process")
            return self._load_existing_results()
        
        logger.info(f"Processing {len(batches)} batches")
        
        all_results = []
        
        for batch_idx, batch in enumerate(batches):
            if self.job_manager.shutdown_requested:
                logger.info("Shutdown requested, stopping processing")
                break
                
            batch_number = initial_stats["max_batch_processed"] + batch_idx + 1
            logger.info(f"Processing batch {batch_number}/{len(batches)} ({len(batch)} emails)")
            
            # Check memory usage
            memory_usage = self.job_manager.get_memory_usage_mb()
            if memory_usage > self.max_memory_mb:
                logger.warning(f"Memory usage ({memory_usage:.1f}MB) exceeds limit ({self.max_memory_mb}MB)")
                logger.info("Forcing garbage collection and continuing")
                import gc
                gc.collect()
            
            # Process batch
            batch_results = self._process_batch(batch, batch_number)
            all_results.extend(batch_results)
            
            # Save results incrementally
            self.job_manager.save_batch_results(batch_results, batch_number)
            
            # Log progress
            current_stats = self.job_manager.get_processing_stats()
            logger.info(f"Batch {batch_number} completed. Total processed: {current_stats['total_processed']}")
        
        # Final stats
        final_stats = self.job_manager.get_processing_stats()
        logger.info(f"Processing completed. Final stats: {final_stats}")
        
        return all_results

    def _process_batch(self, batch: List[Dict[str, Any]], batch_number: int) -> List[IOCResult]:
        """Process a single batch of emails"""
        batch_results = []
        
        for email in batch:
            try:
                # Extract IOCs
                result = self.extractor.extract_iocs_from_email(email)
                batch_results.append(result)
                
                # Mark as processed
                success = len(result.extraction_errors) == 0
                self.job_manager.mark_email_processed(
                    result.email_hash, 
                    result.filename, 
                    batch_number, 
                    result.processing_time_ms, 
                    success
                )
                
            except Exception as e:
                logger.error(f"Failed to process email {email.get('filename', 'unknown')}: {e}")
                
                # Create error result
                email_hash = email.get('_hash', '')
                error_result = IOCResult(
                    filename=email.get('filename', 'unknown'),
                    email_hash=email_hash,
                    extraction_errors=[f"Critical processing error: {str(e)}"]
                )
                batch_results.append(error_result)
                
                # Mark as failed
                self.job_manager.mark_email_processed(
                    email_hash, 
                    email.get('filename', 'unknown'), 
                    batch_number, 
                    0, 
                    False
                )
        
        return batch_results

    def _load_existing_results(self) -> List[IOCResult]:
        """Load existing results from checkpoint"""
        if not self.job_manager.results_path.exists():
            return []
        
        try:
            with open(self.job_manager.results_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return [IOCResult(**item) for item in data]
        except Exception as e:
            logger.error(f"Failed to load existing results: {e}")
            return []

    def get_results_summary(self) -> Dict[str, Any]:
        """Get comprehensive results summary"""
        stats = self.job_manager.get_processing_stats()
        
        # Load results for detailed analysis
        results = self._load_existing_results()
        
        summary = {
            "processing_stats": stats,
            "total_results": len(results),
            "results_with_errors": len([r for r in results if r.extraction_errors]),
            "unique_domains": len(set(domain for r in results for domain in r.domains)),
            "unique_sender_ips": len(set(r.sender_ip for r in results if r.sender_ip)),
            "unique_recipient_ips": len(set(r.recipient_ip for r in results if r.recipient_ip)),
            "total_urls_found": sum(len(r.urls_found) for r in results)
        }
        
        return summary

def find_eml_files(directory: str) -> List[str]:
    """Recursively find all .eml files in the given directory."""
    eml_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.eml'):
                eml_files.append(os.path.join(root, file))
    return eml_files

def parse_eml_file(filepath: str) -> Dict[str, Any]:
    """Parse an .eml file and extract relevant fields into a dict, including sender/recipient IPs from Received headers."""
    with open(filepath, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    
    def get_addr(header):
        return str(msg[header]) if msg[header] else ''
    
    # Extract body (prefer text/html, fallback to text/plain)
    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == 'text/html':
                body = part.get_content()
                break
            elif ctype == 'text/plain' and not body:
                body = part.get_content()
    else:
        body = msg.get_content()

    # Extract sender and recipient IPs from Received headers
    received_headers = msg.get_all('Received', [])
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    received_ips = []
    for header in received_headers:
        ips = ip_pattern.findall(header)
        received_ips.extend(ips)
    sender_ip = received_ips[-1] if received_ips else ''  # Earliest (last) Received header
    recipient_ip = received_ips[0] if received_ips else ''  # Most recent (first) Received header

    return {
        'filename': os.path.basename(filepath),
        'from': get_addr('from'),
        'to': get_addr('to'),
        'sender_ip': sender_ip,
        'recipient_ip': recipient_ip,
        'subject': str(msg['subject']) if msg['subject'] else '',
        'body': body or ''
    }

def export_clean_iocs(input_path, output_path_json, output_path_ndjson):
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    # Write pretty JSON array
    with open(output_path_json, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    # Write NDJSON (one JSON object per line)
    with open(output_path_ndjson, 'w', encoding='utf-8') as f:
        for item in data:
            f.write(json.dumps(item) + '\n')

def send_iocs_to_elasticsearch(json_path, es_url, username, password, index_name='iocs'):
    es = Elasticsearch(es_url, basic_auth=(username, password), verify_certs=True)
    with open(json_path, 'r', encoding='utf-8') as f:
        iocs = json.load(f)
    for ioc in iocs:
        es.index(index=index_name, document=ioc)
    print(f"Sent {len(iocs)} IOCs to Elasticsearch index '{index_name}'")

def generate_kibana_dashboard(ioc_data, output_path='ioc_dashboard.ndjson'):
    """Generate Kibana dashboard configuration based on IOC data"""
    
    dashboard_config = []
    
    # 1. Index Pattern (simplified)
    index_pattern = {
        "type": "index-pattern",
        "id": "iocs",
        "attributes": {
            "title": "iocs",
            "timeFieldName": "processed_at"
        }
    }
    dashboard_config.append(index_pattern)
    
    # 2. Visualizations (updated to handle null values and arrays)
    visualizations = [
        {
            "id": "vis_1",
            "title": "Top Sender Emails",
            "field": "sender_email.keyword",
            "filter": "sender_email:*"
        },
        {
            "id": "vis_2", 
            "title": "Top Sender IPs",
            "field": "sender_ip.keyword",
            "filter": "sender_ip:*"
        },
        {
            "id": "vis_3",
            "title": "Top Recipient Emails", 
            "field": "recipient_email.keyword",
            "filter": "recipient_email:*"
        },
        {
            "id": "vis_4",
            "title": "Top Recipient IPs",
            "field": "recipient_ip.keyword",
            "filter": "recipient_ip:*"
        },
        {
            "id": "vis_5",
            "title": "Top Email Subjects",
            "field": "subject.keyword",
            "filter": "subject:*"
        },
        {
            "id": "vis_6",
            "title": "Top Domains",
            "field": "domains.keyword",
            "filter": "domains:*"
        }
    ]
    
    # Generate each visualization
    for viz in visualizations:
        # All fields now use .keyword subfield for proper aggregation
        vis_state = {
            "title": viz["title"],
            "type": "pie",
            "params": {
                "type": "pie",
                "addLegend": True,
                "addTooltip": True,
                "isDonut": True
            },
            "aggs": [
                {
                    "id": "1",
                    "enabled": True,
                    "type": "count",
                    "schema": "metric",
                    "params": {}
                },
                {
                    "id": "2",
                    "enabled": True,
                    "type": "terms",
                    "schema": "segment",
                    "params": {
                        "field": viz["field"],
                        "size": 10,
                        "order": "desc",
                        "orderBy": "1"
                    }
                }
            ]
        }
        
        # Add filter to exclude null values
        query = {"query": viz["filter"], "language": "kuery"} if viz["filter"] else {"query": "", "language": "kuery"}
        
        visualization = {
            "type": "visualization",
            "id": viz["id"],
            "attributes": {
                "title": viz["title"],
                "visState": json.dumps(vis_state),
                "uiStateJSON": "{}",
                "description": "",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "iocs",
                        "query": query,
                        "filter": []
                    })
                }
            }
        }
        dashboard_config.append(visualization)
    
    # 3. Dashboard
    panels = []
    for i, viz in enumerate(visualizations):
        panel = {
            "panelIndex": str(i + 1),
            "gridData": {
                "x": (i % 2) * 24,
                "y": (i // 2) * 15,
                "w": 24,
                "h": 15,
                "i": str(i + 1)
            },
            "version": "7.10.0",
            "type": "visualization",
            "id": viz["id"]
        }
        panels.append(panel)
    
    dashboard = {
        "type": "dashboard",
        "id": "ioc-dashboard",
        "attributes": {
            "title": "IOC Overview",
            "hits": 0,
            "description": "Dashboard of email IOC extractions",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({
                "useMargins": True,
                "hidePanelTitles": False
            }),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"language": "kuery", "query": ""},
                    "filter": []
                })
            }
        }
    }
    dashboard_config.append(dashboard)
    
    # Write NDJSON file
    with open(output_path, 'w', encoding='utf-8') as f:
        for item in dashboard_config:
            f.write(json.dumps(item) + '\n')
    
    print(f"Generated Kibana dashboard configuration: {output_path}")
    print(f"Dashboard ID: ioc-dashboard")
    print("Import this file into Kibana via: Stack Management > Saved Objects > Import")

def import_dashboard_to_kibana(dashboard_path, kibana_url, api_key):
    """Automatically import dashboard into Kibana via API using API key authentication"""
    try:
        with open(dashboard_path, 'rb') as f:
            files = {'file': (os.path.basename(dashboard_path), f, 'application/ndjson')}
            import_url = f"{kibana_url}/api/saved_objects/_import?overwrite=true"
            headers = {'kbn-xsrf': 'true', 'Authorization': f'ApiKey {api_key}'}
            response = requests.post(
                import_url,
                headers=headers,
                files=files,
                verify=True
            )
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Dashboard imported successfully!")
            print(f"   - Successfully imported: {result.get('successCount', 0)} objects")
            print(f"   - Errors: {result.get('errors', [])}")
            print(f"   - Dashboard will be available in Kibana at: {kibana_url}/app/dashboards")
            return True
        else:
            print(f"❌ Failed to import dashboard. Status: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Error importing dashboard: {e}")
        return False

# Validation Configuration - Easy to switch on/off
VALIDATION_CONFIG = {
    'enabled': True,  # Master switch for all validations
    'check_file_exists': True,
    'check_json_structure': True,
    'check_data_types': True,
    'check_required_fields': True,
    'check_data_quality': True,
    'check_empty_data': True,
    'verbose_output': True  # Detailed validation messages
}

def validate_ioc_data(json_file_path: str) -> Dict[str, Any]:
    """Comprehensive validation of IOC data with configurable checks"""
    validation_results = {
        'overall_valid': False,
        'checks_passed': 0,
        'checks_failed': 0,
        'errors': [],
        'warnings': [],
        'data_summary': {}
    }
    
    if not VALIDATION_CONFIG['enabled']:
        if VALIDATION_CONFIG['verbose_output']:
            print("🔧 Data validation disabled by configuration")
        validation_results['overall_valid'] = True
        return validation_results
    
    print("\n🔍 Starting IOC data validation...")
    
    # Check 1: File exists
    if VALIDATION_CONFIG['check_file_exists']:
        if not os.path.exists(json_file_path):
            error_msg = f"❌ IOC file not found: {json_file_path}"
            validation_results['errors'].append(error_msg)
            validation_results['checks_failed'] += 1
            if VALIDATION_CONFIG['verbose_output']:
                print(error_msg)
        else:
            validation_results['checks_passed'] += 1
            if VALIDATION_CONFIG['verbose_output']:
                print(f"✅ File exists: {json_file_path}")
    
    # Check 2: JSON structure
    if VALIDATION_CONFIG['check_json_structure'] and os.path.exists(json_file_path):
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                error_msg = "❌ Invalid JSON structure: Expected list/array"
                validation_results['errors'].append(error_msg)
                validation_results['checks_failed'] += 1
                if VALIDATION_CONFIG['verbose_output']:
                    print(error_msg)
            else:
                validation_results['checks_passed'] += 1
                validation_results['data_summary']['total_records'] = len(data)
                if VALIDATION_CONFIG['verbose_output']:
                    print(f"✅ Valid JSON structure: {len(data)} records found")
        except json.JSONDecodeError as e:
            error_msg = f"❌ Invalid JSON format: {str(e)}"
            validation_results['errors'].append(error_msg)
            validation_results['checks_failed'] += 1
            if VALIDATION_CONFIG['verbose_output']:
                print(error_msg)
            return validation_results
        except Exception as e:
            error_msg = f"❌ Error reading JSON file: {str(e)}"
            validation_results['errors'].append(error_msg)
            validation_results['checks_failed'] += 1
            if VALIDATION_CONFIG['verbose_output']:
                print(error_msg)
            return validation_results
    
    # Check 3: Empty data
    if VALIDATION_CONFIG['check_empty_data'] and 'data_summary' in validation_results:
        if validation_results['data_summary'].get('total_records', 0) == 0:
            error_msg = "❌ No IOC records found in file"
            validation_results['errors'].append(error_msg)
            validation_results['checks_failed'] += 1
            if VALIDATION_CONFIG['verbose_output']:
                print(error_msg)
        else:
            validation_results['checks_passed'] += 1
            if VALIDATION_CONFIG['verbose_output']:
                print(f"✅ Data contains {validation_results['data_summary']['total_records']} records")
    
    # Check 4: Data types and required fields
    if VALIDATION_CONFIG['check_data_types'] and 'data_summary' in validation_results and validation_results['data_summary'].get('total_records', 0) > 0:
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            required_fields = ['filename', 'email_hash', 'processed_at']
            optional_fields = ['sender_email', 'sender_ip', 'recipient_email', 'recipient_ip', 'subject', 'links', 'domains', 'urls_found', 'extraction_errors']
            
            valid_records = 0
            invalid_records = 0
            
            for i, record in enumerate(data):
                record_valid = True
                
                # Check required fields
                if VALIDATION_CONFIG['check_required_fields']:
                    for field in required_fields:
                        if field not in record:
                            error_msg = f"❌ Record {i}: Missing required field '{field}'"
                            validation_results['errors'].append(error_msg)
                            record_valid = False
                        elif not isinstance(record[field], str):
                            error_msg = f"❌ Record {i}: Field '{field}' must be string, got {type(record[field]).__name__}"
                            validation_results['errors'].append(error_msg)
                            record_valid = False
                
                # Check data types for optional fields
                if VALIDATION_CONFIG['check_data_types']:
                    # Check lists
                    for field in ['links', 'domains', 'urls_found', 'extraction_errors']:
                        if field in record and not isinstance(record[field], list):
                            error_msg = f"❌ Record {i}: Field '{field}' must be list, got {type(record[field]).__name__}"
                            validation_results['errors'].append(error_msg)
                            record_valid = False
                    
                    # Check optional string fields
                    for field in ['sender_email', 'sender_ip', 'recipient_email', 'recipient_ip', 'subject']:
                        if field in record and record[field] is not None and not isinstance(record[field], str):
                            error_msg = f"❌ Record {i}: Field '{field}' must be string or null, got {type(record[field]).__name__}"
                            validation_results['errors'].append(error_msg)
                            record_valid = False
                
                if record_valid:
                    valid_records += 1
                else:
                    invalid_records += 1
            
            validation_results['data_summary']['valid_records'] = valid_records
            validation_results['data_summary']['invalid_records'] = invalid_records
            
            if valid_records > 0:
                validation_results['checks_passed'] += 1
                if VALIDATION_CONFIG['verbose_output']:
                    print(f"✅ Data types validation: {valid_records} valid records, {invalid_records} invalid")
            else:
                validation_results['checks_failed'] += 1
                if VALIDATION_CONFIG['verbose_output']:
                    print(f"❌ All records failed data type validation")
                    
        except Exception as e:
            error_msg = f"❌ Error during data type validation: {str(e)}"
            validation_results['errors'].append(error_msg)
            validation_results['checks_failed'] += 1
            if VALIDATION_CONFIG['verbose_output']:
                print(error_msg)
    
    # Check 5: Data quality
    if VALIDATION_CONFIG['check_data_quality'] and 'data_summary' in validation_results and validation_results['data_summary'].get('valid_records', 0) > 0:
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            quality_issues = 0
            total_domains = 0
            total_urls = 0
            total_ips = 0
            
            for i, record in enumerate(data):
                # Check for suspicious patterns
                if 'domains' in record and isinstance(record['domains'], list):
                    total_domains += len(record['domains'])
                    for domain in record['domains']:
                        if isinstance(domain, str) and len(domain) < 3:
                            quality_issues += 1
                            if VALIDATION_CONFIG['verbose_output']:
                                validation_results['warnings'].append(f"⚠️ Record {i}: Suspiciously short domain: {domain}")
                
                if 'urls_found' in record and isinstance(record['urls_found'], list):
                    total_urls += len(record['urls_found'])
                
                if 'sender_ip' in record and record['sender_ip']:
                    total_ips += 1
                
                if 'recipient_ip' in record and record['recipient_ip']:
                    total_ips += 1
            
            validation_results['data_summary']['total_domains'] = total_domains
            validation_results['data_summary']['total_urls'] = total_urls
            validation_results['data_summary']['total_ips'] = total_ips
            validation_results['data_summary']['quality_issues'] = quality_issues
            
            if quality_issues == 0:
                validation_results['checks_passed'] += 1
                if VALIDATION_CONFIG['verbose_output']:
                    print(f"✅ Data quality check passed: {total_domains} domains, {total_urls} URLs, {total_ips} IPs")
            else:
                validation_results['checks_failed'] += 1
                if VALIDATION_CONFIG['verbose_output']:
                    print(f"⚠️ Data quality issues found: {quality_issues} warnings")
                    
        except Exception as e:
            error_msg = f"❌ Error during data quality validation: {str(e)}"
            validation_results['errors'].append(error_msg)
            validation_results['checks_failed'] += 1
            if VALIDATION_CONFIG['verbose_output']:
                print(error_msg)
    
    # Final validation result
    if validation_results['checks_failed'] == 0 and validation_results['checks_passed'] > 0:
        validation_results['overall_valid'] = True
        print(f"✅ IOC data validation PASSED ({validation_results['checks_passed']} checks passed)")
    else:
        validation_results['overall_valid'] = False
        print(f"❌ IOC data validation FAILED ({validation_results['checks_failed']} checks failed)")
    
    # Print summary
    if validation_results['data_summary']:
        summary = validation_results['data_summary']
        print(f"📊 Data Summary:")
        print(f"   - Total records: {summary.get('total_records', 0)}")
        print(f"   - Valid records: {summary.get('valid_records', 0)}")
        print(f"   - Invalid records: {summary.get('invalid_records', 0)}")
        print(f"   - Total domains: {summary.get('total_domains', 0)}")
        print(f"   - Total URLs: {summary.get('total_urls', 0)}")
        print(f"   - Total IPs: {summary.get('total_ips', 0)}")
        print(f"   - Quality issues: {summary.get('quality_issues', 0)}")
    
    return validation_results

def generate_mock_ioc_data(num_records: int = 10) -> List[Dict[str, Any]]:
    """Generate mock IOC data with no null values for testing/control group"""
    import random
    
    mock_sender_emails = [
        "attacker@malicious-domain.com",
        "phishing@fake-bank.net", 
        "spam@dodgy-site.org",
        "malware@evil-corp.biz",
        "scam@fraudulent-service.info"
    ]
    
    mock_recipient_emails = [
        "victim@company.com",
        "user@target-org.net",
        "customer@bank.com",
        "employee@corporate.org",
        "admin@business.biz"
    ]
    
    mock_sender_ips = [
        "192.168.1.100",
        "10.0.0.50", 
        "172.16.0.25",
        "203.0.113.42",
        "198.51.100.123"
    ]
    
    mock_recipient_ips = [
        "192.168.1.200",
        "10.0.0.100",
        "172.16.0.50", 
        "203.0.113.100",
        "198.51.100.200"
    ]
    
    mock_subjects = [
        "Urgent: Account Verification Required",
        "Security Alert: Suspicious Activity Detected",
        "Important: Password Reset Request",
        "Invoice Payment Overdue",
        "System Maintenance Notification",
        "Your Account Has Been Compromised",
        "Payment Confirmation Required",
        "Document Review Needed",
        "Security Update Required",
        "Account Suspension Notice"
    ]
    
    mock_domains = [
        "malicious-invoice.com",
        "fake-bank-verify.net",
        "phishing-site.org",
        "scam-service.biz",
        "evil-corp.info",
        "dodgy-payment.com",
        "fraudulent-login.net",
        "malware-download.org",
        "spam-campaign.biz",
        "attack-vector.info"
    ]
    
    mock_urls = [
        "https://malicious-invoice.com/pay",
        "http://fake-bank-verify.net/login",
        "https://phishing-site.org/verify",
        "http://scam-service.biz/confirm",
        "https://evil-corp.info/download",
        "http://dodgy-payment.com/process",
        "https://fraudulent-login.net/auth",
        "http://malware-download.org/file",
        "https://spam-campaign.biz/click",
        "http://attack-vector.info/exploit"
    ]
    
    mock_data = []
    
    for i in range(num_records):
        # Generate random combinations
        sender_email = random.choice(mock_sender_emails)
        recipient_email = random.choice(mock_recipient_emails)
        sender_ip = random.choice(mock_sender_ips)
        recipient_ip = random.choice(mock_recipient_ips)
        subject = random.choice(mock_subjects)
        
        # Generate random number of domains and URLs
        num_domains = random.randint(2, 5)
        num_urls = random.randint(3, 8)
        
        domains = random.sample(mock_domains, min(num_domains, len(mock_domains)))
        urls = random.sample(mock_urls, min(num_urls, len(mock_urls)))
        
        # Add some random domains and URLs
        extra_domains = [f"random-domain-{j}.com" for j in range(random.randint(1, 3))]
        extra_urls = [f"https://random-url-{j}.net" for j in range(random.randint(1, 3))]
        
        domains.extend(extra_domains)
        urls.extend(extra_urls)
        
        mock_record = {
            "filename": f"mock_email_{i+1}.eml",
            "email_hash": hashlib.sha256(f"mock_data_{i}_{time.time()}".encode()).hexdigest(),
            "sender_email": sender_email,
            "sender_ip": sender_ip,
            "recipient_email": recipient_email,
            "recipient_ip": recipient_ip,
            "subject": subject,
            "links": urls.copy(),
            "domains": domains.copy(),
            "urls_found": urls.copy(),
            "extraction_errors": [],  # No errors in mock data
            "processed_at": datetime.now().isoformat(),
            "processing_time_ms": random.randint(10, 100)
        }
        
        mock_data.append(mock_record)
    
    return mock_data

def export_mock_control_data(num_records: int = 10, output_path_json: str = 'mock_control.json', output_path_ndjson: str = 'mock_control.ndjson'):
    """Export mock control data to JSON files"""
    print(f"\n🧪 Generating mock control data ({num_records} records)...")
    
    mock_data = generate_mock_ioc_data(num_records)
    
    # Write pretty JSON array
    with open(output_path_json, 'w', encoding='utf-8') as f:
        json.dump(mock_data, f, indent=2, ensure_ascii=False)
    
    # Write NDJSON (one JSON object per line)
    with open(output_path_ndjson, 'w', encoding='utf-8') as f:
        for item in mock_data:
            f.write(json.dumps(item) + '\n')
    
    print(f"✅ Mock control data exported:")
    print(f"   - JSON: {output_path_json}")
    print(f"   - NDJSON: {output_path_ndjson}")
    print(f"   - Records: {len(mock_data)}")
    print(f"   - No null values in any field")

def send_mock_data_to_elasticsearch(json_path: str, es_url: str, username: str, password: str, index_name: str = 'mock-iocs'):
    es = Elasticsearch(es_url, basic_auth=(username, password), verify_certs=True)
    
    with open(json_path, 'r', encoding='utf-8') as f:
        mock_iocs = json.load(f)
    
    for ioc in mock_iocs:
        es.index(index=index_name, document=ioc)
    
    print(f"✅ Sent {len(mock_iocs)} mock IOCs to Elasticsearch index '{index_name}'")

def generate_mock_dashboard(output_path='mock_dashboard.ndjson'):
    """Generate Kibana dashboard for mock control data"""
    dashboard_config = []
    
    # 1. Index Pattern for mock data
    index_pattern = {
        "type": "index-pattern",
        "id": "mock-iocs",
        "attributes": {
            "title": "mock-iocs",
            "timeFieldName": "processed_at"
        }
    }
    dashboard_config.append(index_pattern)
    
    # 2. Visualizations for mock data (no filters needed since no null values)
    visualizations = [
        {
            "id": "mock_vis_1",
            "title": "Mock - Top Sender Emails",
            "field": "sender_email.keyword"
        },
        {
            "id": "mock_vis_2", 
            "title": "Mock - Top Sender IPs",
            "field": "sender_ip.keyword"
        },
        {
            "id": "mock_vis_3",
            "title": "Mock - Top Recipient Emails", 
            "field": "recipient_email.keyword"
        },
        {
            "id": "mock_vis_4",
            "title": "Mock - Top Recipient IPs",
            "field": "recipient_ip.keyword"
        },
        {
            "id": "mock_vis_5",
            "title": "Mock - Top Email Subjects",
            "field": "subject.keyword"
        },
        {
            "id": "mock_vis_6",
            "title": "Mock - Top Domains",
            "field": "domains.keyword"
        }
    ]
    
    # Generate each visualization
    for viz in visualizations:
        # All fields now use .keyword subfield for proper aggregation
        vis_state = {
            "title": viz["title"],
            "type": "pie",
            "params": {
                "type": "pie",
                "addLegend": True,
                "addTooltip": True,
                "isDonut": True
            },
            "aggs": [
                {
                    "id": "1",
                    "enabled": True,
                    "type": "count",
                    "schema": "metric",
                    "params": {}
                },
                {
                    "id": "2",
                    "enabled": True,
                    "type": "terms",
                    "schema": "segment",
                    "params": {
                        "field": viz["field"],
                        "size": 10,
                        "order": "desc",
                        "orderBy": "1"
                    }
                }
            ]
        }
        
        visualization = {
            "type": "visualization",
            "id": viz["id"],
            "attributes": {
                "title": viz["title"],
                "visState": json.dumps(vis_state),
                "uiStateJSON": "{}",
                "description": "",
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "mock-iocs",
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                }
            }
        }
        dashboard_config.append(visualization)
    
    # 3. Dashboard
    panels = []
    for i, viz in enumerate(visualizations):
        panel = {
            "panelIndex": str(i + 1),
            "gridData": {
                "x": (i % 2) * 24,
                "y": (i // 2) * 15,
                "w": 24,
                "h": 15,
                "i": str(i + 1)
            },
            "version": "7.10.0",
            "type": "visualization",
            "id": viz["id"]
        }
        panels.append(panel)
    
    dashboard = {
        "type": "dashboard",
        "id": "mock-ioc-dashboard",
        "attributes": {
            "title": "Mock IOC Control Dashboard",
            "hits": 0,
            "description": "Control dashboard with mock IOC data (no null values)",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({
                "useMargins": True,
                "hidePanelTitles": False
            }),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"language": "kuery", "query": ""},
                    "filter": []
                })
            }
        }
    }
    dashboard_config.append(dashboard)
    
    # Write NDJSON file
    with open(output_path, 'w', encoding='utf-8') as f:
        for item in dashboard_config:
            f.write(json.dumps(item) + '\n')
    
    print(f"Generated Mock Dashboard: {output_path}")
    print(f"Dashboard ID: mock-ioc-dashboard")

def main():
    """Main function demonstrating usage with restart capability"""
    
    print("="*60)
    print("📧 IOC EXTRACTOR - EMAIL ANALYSIS TOOL")
    print("="*60)
    
    # Find all .eml files in the current directory
    print("\n🔍 Scanning for .eml files...")
    eml_files = find_eml_files('.')
    
    if not eml_files:
        print("❌ No .eml files found in the current directory.")
        print("   Please place .eml files in the current directory and run the script again.")
        return
    
    # Display file discovery results
    print(f"\n✅ Found {len(eml_files)} .eml file(s):")
    print("-" * 60)
    for i, filepath in enumerate(eml_files, 1):
        # Get file size
        try:
            file_size = os.path.getsize(filepath)
            size_str = f"{file_size:,} bytes"
            if file_size > 1024:
                size_str = f"{file_size/1024:.1f} KB"
            if file_size > 1024*1024:
                size_str = f"{file_size/(1024*1024):.1f} MB"
        except:
            size_str = "unknown size"
        
        # Get relative path for cleaner display
        rel_path = os.path.relpath(filepath, '.')
        print(f"  {i:2d}. {rel_path} ({size_str})")
    
    print("-" * 60)
    print(f"📊 Total: {len(eml_files)} .eml file(s) ready for processing")
    print()
    
    # Parse all .eml files
    print("📖 Parsing .eml files...")
    emails = []
    failed_files = []
    
    for filepath in eml_files:
        try:
            email_data = parse_eml_file(filepath)
            emails.append(email_data)
            print(f"  ✅ {os.path.basename(filepath)} - parsed successfully")
        except Exception as e:
            logger.error(f"Failed to parse {filepath}: {e}")
            failed_files.append((filepath, str(e)))
            print(f"  ❌ {os.path.basename(filepath)} - parsing failed: {str(e)}")
    
    if failed_files:
        print(f"\n⚠️  Warning: {len(failed_files)} file(s) failed to parse:")
        for filepath, error in failed_files:
            print(f"     - {os.path.basename(filepath)}: {error}")
    
    if not emails:
        print("\n❌ No valid .eml files could be parsed.")
        print("   Please check the file format and try again.")
        return
    
    print(f"\n✅ Successfully parsed {len(emails)} out of {len(eml_files)} .eml file(s)")
    
    # Initialize processor with small batch size for demonstration
    processor = ResumableIOCProcessor(batch_size=2, max_memory_mb=256)
    
    try:
        # Process emails (this can be restarted)
        print(f"\n🔄 Processing {len(emails)} email(s) for IOC extraction...")
        results = processor.process_emails(emails)
        
        # Get summary
        summary = processor.get_results_summary()
        print("\n" + "="*60)
        print("📊 PROCESSING SUMMARY")
        print("="*60)
        for key, value in summary.items():
            print(f"{key}: {value}")
        
        # Display recent results
        print("\n" + "="*60)
        print("📋 RECENT RESULTS (Last 3)")
        print("="*60)
        for result in results[-3:]:  # Show last 3 results
            print(f"\n📧 File: {result.filename}")
            print(f"   📤 Sender Email: {result.sender_email}")
            print(f"   🌐 Sender IP: {result.sender_ip}")
            print(f"   📥 Recipient Email: {result.recipient_email}")
            print(f"   🌐 Recipient IP: {result.recipient_ip}")
            print(f"   📝 Subject: {result.subject}")
            print(f"   🔗 Links Found: {len(result.links)}")
            print(f"   🌍 Domains: {len(result.domains)}")
            print(f"   ⏱️  Processing Time: {result.processing_time_ms}ms")
            if result.extraction_errors:
                print(f"   ⚠️  Errors: {result.extraction_errors}")
            print("-" * 50)
        
        print(f"\n💾 Results saved to: {processor.job_manager.results_path}")
        print(f"💾 Checkpoints saved to: {processor.job_manager.checkpoint_dir}")
        
        # --- Export IOCs to JSON and forward to Elasticsearch ---
        export_path_json = 'ioc_export.json'
        export_path_ndjson = 'ioc_export.ndjson'
        print(f"\n📤 Exporting IOCs to {export_path_json} and {export_path_ndjson} ...")
        export_clean_iocs(str(processor.job_manager.results_path), export_path_json, export_path_ndjson)
        print("✅ Export complete.")
        
        # Validate IOC data before proceeding
        validation_result = validate_ioc_data(export_path_json)
        
        if not validation_result['overall_valid']:
            print("\n❌ IOC data validation failed. Stopping pipeline.")
            print("Please check the validation errors above and fix the data issues.")
            return
        
        # Forward to Elasticsearch (only if validation passed)
        es_url = 'https://my-deployment-90153e.es.us-east-1.aws.found.io'
        es_username = "superuser2"
        es_password = "Wsag2AZU!@#qwe!@#"
        es_index = 'iocs'
        print(f"\n🚀 Forwarding IOCs to Elasticsearch at {es_url} (index: {es_index}) ...")
        send_iocs_to_elasticsearch(export_path_json, es_url, es_username, es_password, es_index)
        print("✅ Forwarding complete.")
        
        # Generate Kibana Dashboard
        print(f"\n📊 Generating Kibana dashboard configuration...")
        generate_kibana_dashboard(ioc_data=None, output_path='ioc_dashboard.ndjson')
        print("✅ Dashboard generation complete.")
        
        # Automatically import dashboard to Kibana
        kibana_url = 'https://my-deployment-90153e.kb.us-east-1.aws.found.io'
        kibana_api_key = 'OXZHckRKZ0JfcFJkdUVqUmZIbFo6V1ROVTdOR1Z5dDlsRzR1Ums2amlzUQ=='
        print(f"\n📥 Importing dashboard to Kibana at {kibana_url}...")
        import_dashboard_to_kibana('ioc_dashboard.ndjson', kibana_url, kibana_api_key)
        print("✅ Dashboard import complete.")
        
        # --- MOCK CONTROL DATA PATH ---
        print(f"\n" + "="*60)
        print("🧪 MOCK CONTROL DATA PATH")
        print("="*60)
        
        # Generate and export mock control data
        export_mock_control_data(num_records=15, output_path_json='mock_control.json', output_path_ndjson='mock_control.ndjson')
        
        # Validate mock data
        mock_validation_result = validate_ioc_data('mock_control.json')
        
        if mock_validation_result['overall_valid']:
            # Send mock data to separate Elasticsearch index
            print(f"\n🚀 Forwarding mock control data to Elasticsearch...")
            send_mock_data_to_elasticsearch('mock_control.json', es_url, es_username, es_password, 'mock-iocs')
            print("✅ Mock data forwarding complete.")
            
            # Generate and import mock dashboard
            print(f"\n📊 Generating mock dashboard configuration...")
            generate_mock_dashboard('mock_dashboard.ndjson')
            print("✅ Mock dashboard generation complete.")
            
            print(f"\n📥 Importing mock dashboard to Kibana...")
            import_dashboard_to_kibana('mock_dashboard.ndjson', kibana_url, kibana_api_key)
            print("✅ Mock dashboard import complete.")
        else:
            print("❌ Mock data validation failed. Skipping mock data pipeline.")
        
        print(f"\n" + "="*60)
        print("✅ COMPLETE PIPELINE SUMMARY")
        print("="*60)
        print("📊 Real Data:")
        print(f"   - JSON: {export_path_json}")
        print(f"   - NDJSON: {export_path_ndjson}")
        print(f"   - Elasticsearch Index: {es_index}")
        print(f"   - Dashboard: ioc-dashboard")
        print("🧪 Mock Control Data:")
        print(f"   - JSON: mock_control.json")
        print(f"   - NDJSON: mock_control.ndjson")
        print(f"   - Elasticsearch Index: mock-iocs")
        print(f"   - Dashboard: mock-ioc-dashboard")
        print("="*60)
        # --------------------------------------------------------
        
    except KeyboardInterrupt:
        logger.info("Processing interrupted by user")
        print("\n⏹️  Processing interrupted. You can restart the script to continue from where it left off.")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"❌ Error occurred: {e}")
        print("Check logs for details. You can restart the script to continue processing.")

if __name__ == "__main__":
    main()