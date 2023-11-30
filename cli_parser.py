# cli_parser.py
import argparse
import datetime

def parse_arguments():
    parser = argparse.ArgumentParser(description="Get the Patch Tuesday info")
    # ... (existing argument definitions)
    return parser.parse_args()