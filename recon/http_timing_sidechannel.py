"""HTTP Timing Side Channel for Server Processing Path Analysis.

Sends identical HTTP requests with very slight differences and measures
response timing differences precisely to reveal server-side processing paths.

Timing differences reveal cached vs uncached responses, database-backed
vs static content, WAF processing time, and more - all from response
timing alone without content analysis.
"""

import logging
import time
import statistics
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger("usare.http_timing")

class ProcessingPath(Enum):
    CACHE_HIT = "cache_hit"
    CACHE_MISS = "cache_miss"
    DATABASE_QUERY = "database_query"
    STATIC_CONTENT = "static_content"
    WAF_PROCESSING = "waf_processing"
    APPLICATION_PROCESSING = "application_processing"
    CDN_EDGE = "cdn_edge"
    LOAD_BALANCER = "load_balancer"

@dataclass
class HTTPTimingResult:
    """HTTP timing side channel result."""
    target_host: str
    target_port: int
    processing_paths: List[str]
    timing_differences: Dict[str, float]
    path_confidence: Dict[str, float]
    security_implications: List[str]
    confidence_score: float

class HTTPTimingAnalyzer:
    """Advanced HTTP timing side channel analyzer."""
    
    def __init__(self):
        self.timeout = 10.0
        self.concurrent_requests = 5
        
        # Timing patterns for different processing paths
        self.timing_signatures = {
            ProcessingPath.CACHE_HIT: {
                "timing_range": (0.001, 0.050),  # 1-50ms
                "characteristics": ["very_fast", "consistent", "low_variance"],
                "indicators": ["cache_headers", "fast_response"]
            },
            ProcessingPath.CACHE_MISS: {
                "timing_range": (0.050, 0.500),  # 50-500ms
                "characteristics": ["moderate", "variable", "higher_variance"],
                "indicators": ["cache_miss_headers", "slower_response"]
            },
            ProcessingPath.DATABASE_QUERY: {
                "timing_range": (0.100, 2.000),  # 100-2000ms
                "characteristics": ["slow", "high_variance", "database_indicators"],
                "indicators": ["db_connection_time", "query_processing"]
            },
            ProcessingPath.STATIC_CONTENT: {
                "timing_range": (0.010, 0.100),  # 10-100ms
                "characteristics": ["fast", "consistent", "low_variance"],
                "indicators": ["static_file_serving", "content_length_consistent"]
            },
            ProcessingPath.WAF_PROCESSING: {
                "timing_range": (0.200, 1.500),  # 200-1500ms
                "characteristics": ["slow", "very_high_variance", "security_processing"],
                "indicators": ["security_headers", "analysis_overhead"]
            },
            ProcessingPath.APPLICATION_PROCESSING: {
                "timing_range": (0.050, 1.000),  # 50-1000ms
                "characteristics": ["moderate", "variable", "app_logic"],
                "indicators": ["application_headers", "business_logic"]
            },
            ProcessingPath.CDN_EDGE: {
                "timing_range": (0.020, 0.200),  # 20-200ms
                "characteristics": ["fast", "consistent", "edge_cache"],
                "indicators": ["cdn_headers", "edge_location"]
            },
            ProcessingPath.LOAD_BALANCER: {
                "timing_range": (0.050, 0.300),  # 50-300ms
                "characteristics": ["variable", "multiple_signatures", "backend_diversity"],
                "indicators": ["different_server_headers", "varying_response_times"]
            }
        }
    
    def analyze_http_timing_sidechannel(self, target_host: str, target_port: int = 80) -> HTTPTimingResult:
        """Analyze HTTP timing side channel."""
        start_time = time.time()
        
        try:
            # Generate timing probes
            timing_probes = self._generate_timing_probes(target_host, target_port)
            
            # Execute probes concurrently
            timing_results = self._execute_timing_probes(timing_probes)
            
            # Analyze timing patterns
            processing_paths = self._analyze_timing_patterns(timing_results)
            
            # Calculate timing differences
            timing_differences = self._calculate_timing_differences(timing_results)
            
            # Calculate confidence for each path
            path_confidence = self._calculate_path_confidence(processing_paths, timing_differences)
            
            # Determine security implications
            security_implications = self._assess_security_implications(processing_paths, path_confidence)
            
            # Calculate overall confidence
            overall_confidence = self._calculate_overall_confidence(path_confidence)
            
            return HTTPTimingResult(
                target_host=target_host,
                target_port=target_port,
                processing_paths=processing_paths,
                timing_differences=timing_differences,
                path_confidence=path_confidence,
                security_implications=security_implications,
                confidence_score=overall_confidence
            )
            
        except Exception as e:
            logger.error(f"[HTTP Timing] Side channel analysis failed: {e}")
            return HTTPTimingResult(
                target_host=target_host,
                target_port=target_port,
                processing_paths=[],
                timing_differences={},
                path_confidence={},
                security_implications=[f"analysis_failed: {e}"],
                confidence_score=0.0
            )
    
    def _generate_timing_probes(self, target_host: str, target_port: int) -> List[Dict[str, Any]]:
        """Generate timing probes with slight variations."""
        base_url = f"http://{target_host}:{target_port}"
        
        probes = []
        
        # Base probe (normal request)
        probes.append({
            "name": "base_request",
            "url": base_url,
            "headers": {
                "User-Agent": "Mozilla/5.0 (compatible; TimingAnalyzer/1.0)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive"
            },
            "method": "GET",
            "variation_type": "none"
        })
        
        # Header variation probes
        header_variations = [
            ("X-Timing-Test", "timing_probe_1"),
            ("X-Analysis-Header", "timing_probe_2"),
            ("X-Cache-Control", "timing_probe_3"),
            ("X-Debug-Info", "timing_probe_4")
        ]
        
        for header_name, probe_id in header_variations:
            probes.append({
                "name": f"header_variation_{probe_id}",
                "url": base_url,
                "headers": {
                    "User-Agent": "Mozilla/5.0 (compatible; TimingAnalyzer/1.0)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                    header_name: probe_id
                },
                "method": "GET",
                "variation_type": "header"
            })
        
        # Parameter variation probes
        param_variations = [
            ("?timing_test=1", "param_probe_1"),
            ("?debug=true&timing_test=2", "param_probe_2"),
            ("?cache_bypass=" + "A" * 50, "param_probe_3"),  # Long parameter
            ("?analysis=" + "%20".join(["timing", "test", "4"]), "param_probe_4")  # URL encoded
        ]
        
        for param, probe_id in param_variations:
            probes.append({
                "name": f"param_variation_{probe_id}",
                "url": base_url + param,
                "headers": {
                    "User-Agent": "Mozilla/5.0 (compatible; TimingAnalyzer/1.0)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive"
                },
                "method": "GET",
                "variation_type": "parameter"
            })
        
        # Method variation probes
        method_variations = [
            ("HEAD", "method_probe_1"),
            ("OPTIONS", "method_probe_2"),
            ("POST", "method_probe_3"),
            ("TRACE", "method_probe_4")
        ]
        
        for method, probe_id in method_variations:
            probes.append({
                "name": f"method_variation_{probe_id}",
                "url": base_url,
                "headers": {
                    "User-Agent": "Mozilla/5.0 (compatible; TimingAnalyzer/1.0)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive"
                },
                "method": method,
                "variation_type": "method"
            })
        
        return probes
    
    def _execute_timing_probes(self, probes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Execute timing probes concurrently."""
        if not HAS_REQUESTS:
            return []
        
        results = []
        
        def execute_probe(probe):
            try:
                start_time = time.perf_counter()
                
                response = requests.request(
                    method=probe["method"],
                    url=probe["url"],
                    headers=probe["headers"],
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                end_time = time.perf_counter()
                response_time = (end_time - start_time) * 1000  # Convert to milliseconds
                
                result = {
                    "name": probe["name"],
                    "variation_type": probe["variation_type"],
                    "response_time_ms": response_time,
                    "status_code": response.status_code if response else None,
                    "response_length": len(response.content) if response else 0,
                    "headers": dict(response.headers) if response else {},
                    "success": response is not None
                }
                
                # Add timing signature analysis
                if response:
                    result["timing_signature"] = self._analyze_response_timing(response, response_time)
                
                return result
                
            except Exception as e:
                return {
                    "name": probe["name"],
                    "variation_type": probe["variation_type"],
                    "response_time_ms": 0.0,
                    "status_code": None,
                    "response_length": 0,
                    "headers": {},
                    "success": False,
                    "error": str(e)
                }
        
        # Execute probes with limited concurrency
        threads = []
        for i, probe in enumerate(probes):
            if i >= self.concurrent_requests:
                break
            
            thread = threading.Thread(target=execute_probe, args=(probe,))
            thread.start()
            threads.append(thread)
            
            # Small delay between thread starts to avoid overwhelming
            time.sleep(0.1)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Collect results
        for thread in threads:
            # Get result from thread (this is simplified)
            # In real implementation, we'd use thread-safe result collection
            pass
        
        # For now, execute probes sequentially but with timing precision
        for probe in probes[:self.concurrent_requests]:
            result = execute_probe(probe)
            results.append(result)
        
        return results
    
    def _analyze_response_timing(self, response, response_time: float) -> Dict[str, Any]:
        """Analyze response timing characteristics."""
        if not response:
            return {"analysis": "no_response"}
        
        timing_analysis = {
            "response_time_ms": response_time,
            "server_timing": response.headers.get("Server", ""),
            "cache_control": response.headers.get("Cache-Control", ""),
            "expires": response.headers.get("Expires", ""),
            "etag": response.headers.get("ETag", ""),
            "content_encoding": response.headers.get("Content-Encoding", ""),
            "content_length": response.headers.get("Content-Length", ""),
            "age": response.headers.get("Age", "")
        }
        
        # Analyze timing patterns
        if response_time < 0.050:  # < 50ms
            timing_analysis["speed_category"] = "very_fast"
            timing_analysis["likely_path"] = ProcessingPath.CACHE_HIT
        elif response_time < 0.200:  # < 200ms
            timing_analysis["speed_category"] = "fast"
            timing_analysis["likely_path"] = ProcessingPath.STATIC_CONTENT
        elif response_time < 0.500:  # < 500ms
            timing_analysis["speed_category"] = "moderate"
            timing_analysis["likely_path"] = ProcessingPath.APPLICATION_PROCESSING
        elif response_time < 1.000:  # < 1s
            timing_analysis["speed_category"] = "slow"
            timing_analysis["likely_path"] = ProcessingPath.DATABASE_QUERY
        else:  # >= 1s
            timing_analysis["speed_category"] = "very_slow"
            timing_analysis["likely_path"] = ProcessingPath.WAF_PROCESSING
        
        return timing_analysis
    
    def _analyze_timing_patterns(self, timing_results: List[Dict[str, Any]]) -> List[str]:
        """Analyze timing patterns to identify processing paths."""
        if not timing_results:
            return []
        
        # Group results by timing characteristics
        fast_responses = [r for r in timing_results if r.get("response_time_ms", 0) < 100]
        moderate_responses = [r for r in timing_results if 100 <= r.get("response_time_ms", 0) < 500]
        slow_responses = [r for r in timing_results if r.get("response_time_ms", 0) >= 500]
        
        processing_paths = []
        
        # Analyze fast responses (likely cache hits)
        if fast_responses:
            cache_indicators = []
            for response in fast_responses:
                headers = response.get("headers", {})
                if any(cache_header in headers.get(cache_header, "").lower() 
                      for cache_header in ["cache-control", "expires", "etag", "age"]):
                    cache_indicators.append("cache_headers")
            
            if cache_indicators:
                processing_paths.append(ProcessingPath.CACHE_HIT.value)
        
        # Analyze slow responses (likely database queries)
        if slow_responses:
            db_indicators = []
            for response in slow_responses:
                headers = response.get("headers", {})
                if any(db_indicator in headers.get(db_header, "").lower() 
                      for db_indicator in ["server", "x-powered-by", "x-database"]):
                    db_indicators.append("database_indicators")
            
            if db_indicators:
                processing_paths.append(ProcessingPath.DATABASE_QUERY.value)
        
        # Analyze moderate responses (likely static content)
        if moderate_responses:
            static_indicators = []
            for response in moderate_responses:
                headers = response.get("headers", {})
                if headers.get("content-length"):
                    static_indicators.append("static_content")
            
            if static_indicators:
                processing_paths.append(ProcessingPath.STATIC_CONTENT.value)
        
        # Analyze response patterns for WAF processing
        all_responses = [r for r in timing_results if r.get("success", False)]
        waf_indicators = []
        
        for response in all_responses:
            headers = response.get("headers", {})
            if any(waf_header in headers.get(waf_header, "").lower() 
                  for waf_header in ["x-frame-options", "x-xss-protection", "x-content-type-options"]):
                waf_indicators.append("waf_headers")
            
            # Check for WAF-like timing patterns
            response_time = response.get("response_time_ms", 0)
            if response_time > 200:  # Slow responses might indicate WAF
                timing_variance = self._calculate_timing_variance([r for r in all_responses if r.get("response_time_ms", 0)])
                if timing_variance > 0.5:  # High variance
                    waf_indicators.append("timing_variance")
        
        if waf_indicators:
            processing_paths.append(ProcessingPath.WAF_PROCESSING.value)
        
        # Remove duplicates
        return list(set(processing_paths))
    
    def _calculate_timing_differences(self, timing_results: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate timing differences between probes."""
        timing_differences = {}
        
        if len(timing_results) < 2:
            return timing_differences
        
        # Group by variation type
        base_response = None
        for result in timing_results:
            if result.get("variation_type") == "none":
                base_response = result
                break
        
        if not base_response:
            return timing_differences
        
        # Calculate differences from base response
        for result in timing_results:
            if result.get("success", False):
                base_time = base_response.get("response_time_ms", 0)
                current_time = result.get("response_time_ms", 0)
                
                if base_time > 0:
                    difference = abs(current_time - base_time)
                    timing_differences[result["name"]] = difference
        
        return timing_differences
    
    def _calculate_timing_variance(self, timing_results: List[Dict[str, Any]]) -> float:
        """Calculate timing variance."""
        if len(timing_results) < 2:
            return 0.0
        
        times = [r.get("response_time_ms", 0) for r in timing_results if r.get("response_time_ms", 0) > 0]
        
        if len(times) < 2:
            return 0.0
        
        mean_time = statistics.mean(times)
        variance = statistics.variance(times)
        
        # Normalize variance (0-1 scale)
        if mean_time > 0:
            normalized_variance = variance / (mean_time ** 2)
            return min(1.0, normalized_variance)
        
        return 0.0
    
    def _calculate_path_confidence(self, processing_paths: List[str], 
                                timing_differences: Dict[str, float]) -> Dict[str, float]:
        """Calculate confidence score for each processing path."""
        path_confidence = {}
        
        for path in processing_paths:
            base_confidence = 0.5
            
            # Higher confidence for paths with multiple indicators
            path_results = [r for r in timing_differences.items() 
                           if any(path_indicator in r[0] for path_indicator in self._get_path_indicators(path))]
            
            if len(path_results) > 1:
                base_confidence += 0.2
            
            # Higher confidence for consistent timing patterns
            if path in [ProcessingPath.CACHE_HIT, ProcessingPath.STATIC_CONTENT]:
                base_confidence += 0.2
            
            path_confidence[path] = min(1.0, base_confidence)
        
        return path_confidence
    
    def _get_path_indicators(self, path: str) -> List[str]:
        """Get indicators for specific processing path."""
        indicators = {
            ProcessingPath.CACHE_HIT.value: ["cache_headers", "fast_response", "low_variance"],
            ProcessingPath.CACHE_MISS.value: ["cache_miss_headers", "slower_response"],
            ProcessingPath.DATABASE_QUERY.value: ["database_indicators", "slow_response"],
            ProcessingPath.STATIC_CONTENT.value: ["static_content", "consistent_response"],
            ProcessingPath.WAF_PROCESSING.value: ["waf_headers", "timing_variance", "security_processing"],
            ProcessingPath.APPLICATION_PROCESSING.value: ["application_headers", "business_logic"],
            ProcessingPath.CDN_EDGE.value: ["cdn_headers", "edge_location"],
            ProcessingPath.LOAD_BALANCER.value: ["different_servers", "varying_times"]
        }
        
        return indicators.get(path, [])
    
    def _assess_security_implications(self, processing_paths: List[str], 
                                   path_confidence: Dict[str, float]) -> List[str]:
        """Assess security implications of timing analysis."""
        implications = []
        
        for path in processing_paths:
            confidence = path_confidence.get(path, 0.0)
            
            if path == ProcessingPath.CACHE_HIT.value:
                if confidence > 0.7:
                    implications.append("Cache hit path identified - potential for cache poisoning")
                implications.append("Response timing consistent with cached content")
            
            elif path == ProcessingPath.DATABASE_QUERY.value:
                if confidence > 0.6:
                    implications.append("Database query path identified - potential for SQL injection timing")
                    implications.append("Slow responses indicate database backend")
            
            elif path == ProcessingPath.WAF_PROCESSING.value:
                if confidence > 0.5:
                    implications.append("WAF processing detected - security analysis in progress")
                    implications.append("Timing variance suggests security inspection overhead")
            
            elif path == ProcessingPath.CDN_EDGE.value:
                if confidence > 0.6:
                    implications.append("CDN edge cache identified - geographic distribution possible")
                    implications.append("Edge caching may bypass direct security controls")
            
            elif path == ProcessingPath.LOAD_BALANCER.value:
                if confidence > 0.5:
                    implications.append("Load balancer detected - multiple backend signatures")
                    implications.append("Backend diversity may provide attack surface")
        
        return implications
    
    def _calculate_overall_confidence(self, path_confidence: Dict[str, float]) -> float:
        """Calculate overall confidence score."""
        if not path_confidence:
            return 0.0
        
        # Average confidence across all identified paths
        confidences = list(path_confidence.values())
        if not confidences:
            return 0.0
        
        return statistics.mean(confidences)
    
    def generate_timing_report(self, result: HTTPTimingResult) -> str:
        """Generate human-readable HTTP timing report."""
        report = []
        report.append("HTTP Timing Side Channel Analysis Report")
        report.append("=" * 50)
        report.append(f"Target Host: {result.target_host}")
        report.append(f"Target Port: {result.target_port}")
        report.append(f"Processing Paths: {', '.join(result.processing_paths)}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append("")
        
        # Timing analysis
        report.append("Timing Analysis:")
        for path in result.processing_paths:
            confidence = result.path_confidence.get(path, 0.0)
            report.append(f"  - {path}: {confidence:.2f} confidence")
        report.append("")
        
        # Timing differences
        if result.timing_differences:
            report.append("Timing Differences (ms):")
            for probe_name, difference in result.timing_differences.items():
                if difference > 0:
                    report.append(f"  - {probe_name}: +{difference:.2f}ms")
                else:
                    report.append(f"  - {probe_name}: baseline")
            report.append("")
        
        # Security implications
        if result.security_implications:
            report.append("Security Implications:")
            for implication in result.security_implications:
                report.append(f"  - {implication}")
            report.append("")
        
        # Recommendations
        report.append("Recommendations:")
        if ProcessingPath.WAF_PROCESSING.value in result.processing_paths:
            report.append("  - WAF detected - consider timing-based evasion techniques")
        if ProcessingPath.CACHE_HIT.value in result.processing_paths:
            report.append("  - Cache behavior identified - test cache poisoning possibilities")
        if ProcessingPath.DATABASE_QUERY.value in result.processing_paths:
            report.append("  - Database backend detected - consider blind SQL injection timing")
        if ProcessingPath.LOAD_BALANCER.value in result.processing_paths:
            report.append("  - Load balancer detected - test each backend individually")
        report.append("")
        
        return "\n".join(report)

# Global instance
_http_timing_analyzer = None

def get_http_timing_analyzer() -> HTTPTimingAnalyzer:
    """Get global HTTP timing analyzer."""
    global _http_timing_analyzer
    if _http_timing_analyzer is None:
        _http_timing_analyzer = HTTPTimingAnalyzer()
    return _http_timing_analyzer

def analyze_http_timing_sidechannel(target_host: str, target_port: int = 80) -> HTTPTimingResult:
    """Convenience function for HTTP timing analysis."""
    analyzer = get_http_timing_analyzer()
    return analyzer.analyze_http_timing_sidechannel(target_host, target_port)

def generate_timing_report(result: HTTPTimingResult) -> str:
    """Convenience function for timing report generation."""
    analyzer = get_http_timing_analyzer()
    return analyzer.generate_timing_report(result)
