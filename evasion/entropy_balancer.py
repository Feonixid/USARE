"""Entropy-Balanced Payload Padding for AI-Evasion.

Balances packet entropy to match legitimate traffic patterns and evade
AI-based traffic analysis systems that detect encrypted vs unencrypted traffic.

Chrome 120 TLS handshake: 7.8-8.2 bits/byte entropy
Standard HTTP: 4.5-6.0 bits/byte entropy
DNS queries: 3.5-4.5 bits/byte entropy
"""

import logging
import math
import random
import string
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger("usare.entropy_balancer")

class TrafficType(Enum):
    CHROME_TLS = "chrome_tls"
    FIREFOX_TLS = "firefox_tls"
    HTTP_TRAFFIC = "http_traffic"
    DNS_QUERY = "dns_query"
    VIDEO_STREAMING = "video_streaming"
    GAMING_TRAFFIC = "gaming_traffic"
    VOIP_TRAFFIC = "voip_traffic"

@dataclass
class EntropyProfile:
    """Entropy profile for different traffic types."""
    traffic_type: TrafficType
    target_entropy_bits: float  # Target entropy in bits per byte
    min_entropy: float
    max_entropy: float
    padding_sources: List[str]
    description: str

class EntropyAnalyzer:
    """Analyzes and calculates packet entropy."""
    
    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def calculate_entropy_per_byte(data: bytes) -> float:
        """Calculate entropy per byte."""
        if not data:
            return 0.0
        return EntropyAnalyzer.calculate_shannon_entropy(data) / len(data)

class ContextualPadder:
    """Generates contextually appropriate padding data."""
    
    def __init__(self):
        self.text_samples = self._load_text_samples()
        self.html_samples = self._load_html_samples()
        self.css_samples = self._load_css_samples()
        self.js_samples = self._load_js_samples()
    
    def _load_text_samples(self) -> List[str]:
        """Load realistic text samples for padding."""
        return [
            "The quick brown fox jumps over the lazy dog",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit",
            "In a hole in the ground there lived a hobbit",
            "It was the best of times, it was the worst of times",
            "Call me Ishmael. Some years ago- never mind how long precisely",
            "All happy families are alike; each unhappy family is unhappy in its own way",
            "You don't know about me without you have read a book",
            "Someone must have slandered Josef K., for one morning",
            "The sky above the port was the color of television",
            "We were somewhere around Barstow on the edge of the desert",
            "It is a truth universally acknowledged, that a single man",
            "Many years later, as he faced the firing squad",
            "To the red country and part of the gray country of Oklahoma",
            "He was an old man who fished alone in a skiff",
            "A screaming comes across the sky",
            "I am an invisible man",
            "The story so far: in the beginning, the universe was created",
            "It's a beautiful day, sunny and mild",
            "The first thing I saw was the bright blue sky",
            "She walked into the room with confidence",
            "The computer screen glowed in the dim light"
        ]
    
    def _load_html_samples(self) -> List[str]:
        """Load realistic HTML samples for padding."""
        return [
            "<div class='container'><p>This is sample content</p></div>",
            "<span style='color: blue;'>Important text here</span>",
            "<a href='https://example.com'>Click this link</a>",
            "<img src='image.jpg' alt='Description' width='100' height='100'>",
            "<script type='text/javascript'>console.log('test');</script>",
            "<meta charset='UTF-8'><meta name='viewport' content='width=device-width'>",
            "<link rel='stylesheet' href='styles.css'><title>Page Title</title>",
            "<header><nav><ul><li><a href='#'>Home</a></li></ul></nav></header>",
            "<main><section><article><h1>Article Title</h1></article></section></main>",
            "<footer><p>&copy; 2023 Company Name. All rights reserved.</p></footer>",
            "<form action='/submit' method='post'><input type='text' name='field'></form>",
            "<table><tr><th>Header</th><td>Data</td></tr></table>",
            "<ul class='list'><li>Item one</li><li>Item two</li></ul>",
            "<div id='content' class='main-content'>Content goes here</div>",
            "<button type='button' onclick='handleClick()'>Click me</button>",
            "<select name='options'><option value='1'>Option 1</option></select>",
            "<textarea rows='4' cols='50'>Type here...</textarea>",
            "<iframe src='frame.html' title='Embedded content'></iframe>",
            "<object data='file.pdf' type='application/pdf'></object>",
            "<embed src='video.mp4' type='video/mp4' width='400' height='300'>"
        ]
    
    def _load_css_samples(self) -> List[str]:
        """Load realistic CSS samples for padding."""
        return [
            ".container { max-width: 1200px; margin: 0 auto; padding: 20px; }",
            "body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }",
            ".header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }",
            ".button { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }",
            "@media (max-width: 768px) { .container { padding: 10px; } }",
            ".grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }",
            ".card { box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); border-radius: 8px; }",
            ".text-center { text-align: center; margin: 20px 0; }",
            ".fade-in { animation: fadeIn 0.5s ease-in; }",
            "@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }",
            ".nav { background: #fff; padding: 1rem; position: sticky; top: 0; }",
            ".sidebar { width: 250px; background: #f5f5f5; padding: 20px; }",
            ".content { flex: 1; padding: 20px; min-height: 100vh; }",
            ".footer { background: #333; color: white; text-align: center; padding: 20px; }",
            ".form-group { margin-bottom: 15px; }",
            "input[type='text'] { width: 100%; padding: 8px; border: 1px solid #ddd; }",
            ".alert { padding: 15px; margin: 10px 0; border-radius: 4px; }",
            ".alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }",
            ".modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; }",
            ".dropdown { position: relative; display: inline-block; }",
            ".tooltip { position: relative; display: inline-block; border-bottom: 1px dotted black; }"
        ]
    
    def _load_js_samples(self) -> List[str]:
        """Load realistic JavaScript samples for padding."""
        return [
            "function handleClick(event) { console.log('Button clicked'); }",
            "const data = JSON.parse(response); return data.items || [];",
            "document.addEventListener('DOMContentLoaded', function() { init(); });",
            "if (window.matchMedia('(max-width: 768px)').matches) { mobileMode(); }",
            "const promise = fetch('/api/data').then(res => res.json());",
            "let timer = setInterval(() => { updateStatus(); }, 1000);",
            "function validateForm(form) { return form.checkValidity(); }",
            "const element = document.getElementById('main-content');",
            "array.forEach(item => { processItem(item); });",
            "try { const result = riskyOperation(); } catch (error) { handleError(error); }",
            "class UserManager { constructor() { this.users = []; } }",
            "export default function App() { return <div>Hello World</div>; }",
            "const config = { apiUrl: 'https://api.example.com', timeout: 5000 };",
            "function debounce(func, wait) { let timeout; return function(...args) { clearTimeout(timeout); }; }",
            "const observer = new IntersectionObserver(callback, options);",
            "localStorage.setItem('preferences', JSON.stringify(settings));",
            "const canvas = document.getElementById('chart').getContext('2d');",
            "Promise.all([fetchData1(), fetchData2()]).then(results => { mergeData(results); });",
            "function* generator() { yield 1; yield 2; yield 3; }",
            "const regex = /pattern/g; const matches = text.match(regex);",
            "module.exports = { helper: function() { return 'helper'; } };"
        ]
    
    def generate_padding(self, target_entropy: float, length: int, 
                         source_type: str = "mixed") -> bytes:
        """Generate padding data with specific entropy."""
        if length <= 0:
            return b""
        
        # Select appropriate source based on target entropy
        if target_entropy < 4.0:
            # Low entropy - use structured text
            padding_data = self._generate_low_entropy_padding(length)
        elif target_entropy < 6.0:
            # Medium entropy - mix of text and code
            padding_data = self._generate_medium_entropy_padding(length)
        else:
            # High entropy - use random-like data from code
            padding_data = self._generate_high_entropy_padding(length)
        
        # Adjust to exact length
        if len(padding_data) > length:
            padding_data = padding_data[:length]
        elif len(padding_data) < length:
            padding_data += self._fill_to_length(padding_data, length)
        
        return padding_data
    
    def _generate_low_entropy_padding(self, length: int) -> bytes:
        """Generate low entropy padding (repetitive text)."""
        samples = self.text_samples * 3  # Repeat for variety
        result = ""
        
        for sample in samples:
            result += sample + " "
            if len(result) >= length:
                break
        
        return result.encode('utf-8')[:length]
    
    def _generate_medium_entropy_padding(self, length: int) -> bytes:
        """Generate medium entropy padding (mixed HTML/CSS/JS)."""
        all_samples = self.html_samples + self.css_samples + self.js_samples
        result = ""
        
        for sample in random.sample(all_samples, min(len(all_samples), 20)):
            result += sample + " "
            if len(result) >= length:
                break
        
        return result.encode('utf-8')[:length]
    
    def _generate_high_entropy_padding(self, length: int) -> bytes:
        """Generate high entropy padding (code-like)."""
        samples = self.js_samples + self.css_samples
        result = ""
        
        for sample in random.sample(samples, min(len(samples), 15)):
            result += sample + " "
            if len(result) >= length:
                break
        
        # Add some random characters to increase entropy
        remaining = length - len(result.encode('utf-8'))
        if remaining > 0:
            random_chars = ''.join(random.choices(
                string.ascii_letters + string.digits + string.punctuation,
                k=remaining
            ))
            result += random_chars
        
        return result.encode('utf-8')[:length]
    
    def _fill_to_length(self, data: bytes, target_length: int) -> bytes:
        """Fill data to target length with appropriate entropy."""
        current_entropy = EntropyAnalyzer.calculate_entropy_per_byte(data)
        remaining = target_length - len(data)
        
        if remaining <= 0:
            return data
        
        if current_entropy < 5.0:
            # Add more structured content
            filler = " ".join(random.choices(self.text_samples, k=3))[:remaining]
        else:
            # Add random characters
            filler = ''.join(random.choices(
                string.ascii_letters + string.digits + string.punctuation + " ",
                k=remaining
            ))
        
        return data + filler.encode('utf-8')[:remaining]

class EntropyBalancer:
    """Main entropy balancing system."""
    
    def __init__(self):
        self.analyzer = EntropyAnalyzer()
        self.padder = ContextualPadder()
        self.profiles = self._create_entropy_profiles()
    
    def _create_entropy_profiles(self) -> Dict[TrafficType, EntropyProfile]:
        """Create entropy profiles for different traffic types."""
        return {
            TrafficType.CHROME_TLS: EntropyProfile(
                traffic_type=TrafficType.CHROME_TLS,
                target_entropy_bits=8.0,
                min_entropy=7.8,
                max_entropy=8.2,
                padding_sources=["js", "css", "html"],
                description="Chrome 120 TLS handshake entropy"
            ),
            TrafficType.FIREFOX_TLS: EntropyProfile(
                traffic_type=TrafficType.FIREFOX_TLS,
                target_entropy_bits=7.9,
                min_entropy=7.7,
                max_entropy=8.1,
                padding_sources=["js", "css", "html"],
                description="Firefox 121 TLS handshake entropy"
            ),
            TrafficType.HTTP_TRAFFIC: EntropyProfile(
                traffic_type=TrafficType.HTTP_TRAFFIC,
                target_entropy_bits=5.5,
                min_entropy=4.5,
                max_entropy=6.0,
                padding_sources=["html", "text"],
                description="Standard HTTP traffic entropy"
            ),
            TrafficType.DNS_QUERY: EntropyProfile(
                traffic_type=TrafficType.DNS_QUERY,
                target_entropy_bits=4.0,
                min_entropy=3.5,
                max_entropy=4.5,
                padding_sources=["text"],
                description="DNS query entropy"
            ),
            TrafficType.VIDEO_STREAMING: EntropyProfile(
                traffic_type=TrafficType.VIDEO_STREAMING,
                target_entropy_bits=7.5,
                min_entropy=7.0,
                max_entropy=8.0,
                padding_sources=["js", "css"],
                description="Video streaming traffic entropy"
            ),
            TrafficType.GAMING_TRAFFIC: EntropyProfile(
                traffic_type=TrafficType.GAMING_TRAFFIC,
                target_entropy_bits=6.5,
                min_entropy=6.0,
                max_entropy=7.0,
                padding_sources=["js"],
                description="Gaming traffic entropy"
            ),
            TrafficType.VOIP_TRAFFIC: EntropyProfile(
                traffic_type=TrafficType.VOIP_TRAFFIC,
                target_entropy_bits=6.0,
                min_entropy=5.5,
                max_entropy=6.5,
                padding_sources=["text"],
                description="VoIP traffic entropy"
            )
        }
    
    def balance_packet_entropy(self, data: bytes, target_type: TrafficType,
                              target_size: Optional[int] = None) -> bytes:
        """Balance packet entropy to match target traffic type."""
        if not data:
            return data
        
        profile = self.profiles[target_type]
        current_entropy = self.analyzer.calculate_entropy_per_byte(data)
        
        # Calculate required padding
        if target_size is None:
            target_size = len(data)
        
        padding_needed = max(0, target_size - len(data))
        
        if padding_needed == 0:
            return data
        
        # Generate padding with target entropy
        padding = self.padder.generate_padding(
            profile.target_entropy_bits,
            padding_needed
        )
        
        balanced_data = data + padding
        
        # Verify entropy is within acceptable range
        final_entropy = self.analyzer.calculate_entropy_per_byte(balanced_data)
        
        if not (profile.min_entropy <= final_entropy <= profile.max_entropy):
            # Adjust if needed
            balanced_data = self._fine_tune_entropy(
                balanced_data, profile, target_size
            )
        
        return balanced_data[:target_size]
    
    def _fine_tune_entropy(self, data: bytes, profile: EntropyProfile,
                           target_size: int) -> bytes:
        """Fine-tune entropy to match profile exactly."""
        current_entropy = self.analyzer.calculate_entropy_per_byte(data)
        
        if current_entropy < profile.min_entropy:
            # Need more entropy - add higher entropy content
            extra_padding = self.padder.generate_padding(
                profile.max_entropy,
                target_size - len(data)
            )
        else:
            # Need less entropy - add lower entropy content
            extra_padding = self.padder.generate_padding(
                profile.min_entropy,
                target_size - len(data)
            )
        
        return (data + extra_padding)[:target_size]
    
    def analyze_packet_entropy(self, data: bytes) -> Dict[str, float]:
        """Analyze packet entropy and compare to profiles."""
        entropy_per_byte = self.analyzer.calculate_entropy_per_byte(data)
        
        matches = {}
        for traffic_type, profile in self.profiles.items():
            distance = abs(entropy_per_byte - profile.target_entropy_bits)
            matches[traffic_type.value] = {
                "distance": distance,
                "match_score": max(0, 1 - (distance / 2.0)),  # Normalize to 0-1
                "target_entropy": profile.target_entropy_bits,
                "within_range": profile.min_entropy <= entropy_per_byte <= profile.max_entropy
            }
        
        return {
            "entropy_per_byte": entropy_per_byte,
            "shannon_entropy": self.analyzer.calculate_shannon_entropy(data),
            "data_length": len(data),
            "matches": matches
        }
    
    def get_optimal_profile(self, data: bytes) -> Optional[EntropyProfile]:
        """Get the best matching entropy profile for data."""
        analysis = self.analyze_packet_entropy(data)
        
        best_match = None
        best_score = 0.0
        
        for traffic_type, match_info in analysis["matches"].items():
            if match_info["match_score"] > best_score:
                best_score = match_info["match_score"]
                best_match = TrafficType(traffic_type)
        
        return self.profiles.get(best_match)

# Global instance
_entropy_balancer = None

def get_entropy_balancer() -> EntropyBalancer:
    """Get global entropy balancer instance."""
    global _entropy_balancer
    if _entropy_balancer is None:
        _entropy_balancer = EntropyBalancer()
    return _entropy_balancer

def balance_entropy(data: bytes, traffic_type: str, 
                   target_size: Optional[int] = None) -> bytes:
    """Convenience function for entropy balancing."""
    balancer = get_entropy_balancer()
    
    try:
        type_enum = TrafficType(traffic_type.lower())
    except ValueError:
        type_enum = TrafficType.HTTP_TRAFFIC  # Default
    
    return balancer.balance_packet_entropy(data, type_enum, target_size)

def analyze_entropy(data: bytes) -> Dict[str, any]:
    """Convenience function for entropy analysis."""
    balancer = get_entropy_balancer()
    return balancer.analyze_packet_entropy(data)
