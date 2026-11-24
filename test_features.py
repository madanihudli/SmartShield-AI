import unittest
from src.features import extract_url_features, FEATURE_NAMES

class FeatureTests(unittest.TestCase):
    def test_feature_vector_shape(self):
        self.assertEqual(len(extract_url_features("https://example.com")),len(FEATURE_NAMES))
    def test_suspicious_tokens(self):
        f=extract_url_features("http://example.com/login/verify")
        self.assertGreater(f[21],0)
    def test_ip_host(self):
        f=extract_url_features("http://192.0.2.1/login")
        self.assertEqual(f[3],1)

if __name__=="__main__": unittest.main()
