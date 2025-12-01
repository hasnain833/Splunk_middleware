"""
Test script for Universal Forwarder integration and multiple index support.
This script validates:
- Splunk connection
- Single index queries
- Multiple index queries
- Time range queries
- Data retrieval from Universal Forwarder
"""
import os
import sys
import argparse
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from SplunkConnector import SplunkConnector


def print_header(title):
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_test(test_name, status, details=""):
    """Print test result."""
    status_symbol = "✅" if status else "❌"
    print(f"{status_symbol} {test_name}")
    if details:
        print(f"   {details}")


def test_splunk_connection(splunk):
    """Test basic Splunk connection."""
    print_header("Test 1: Splunk Connection")
    
    try:
        # Try a simple search to test connection
        results = splunk.run_search("index=* | head 1", count=1)
        if results is not None:
            print_test("Connection Test", True, f"Successfully connected to {splunk.base_url}")
            return True
        else:
            print_test("Connection Test", False, "Connection failed - no results returned")
            return False
    except Exception as e:
        print_test("Connection Test", False, f"Error: {str(e)}")
        return False


def test_single_index(splunk, index_name):
    """Test querying a single index."""
    print_header(f"Test 2: Single Index Query - '{index_name}'")
    
    try:
        # Test fetching latest logs
        print(f"   Querying index: {index_name}")
        results = splunk.fetch_latest_logs(index=index_name, minutes=1, limit=5)
        
        if results is not None:
            count = len(results)
            print_test("Single Index Query", True, f"Retrieved {count} events from '{index_name}'")
            
            if count > 0:
                # Show sample event
                sample = results[0]
                print(f"\n   Sample Event:")
                print(f"   - Time: {sample.get('_time', 'N/A')}")
                print(f"   - Host: {sample.get('host', 'N/A')}")
                print(f"   - Sourcetype: {sample.get('sourcetype', 'N/A')}")
                print(f"   - Source: {sample.get('source', 'N/A')}")
            
            return True
        else:
            print_test("Single Index Query", False, "No results returned")
            return False
    except Exception as e:
        print_test("Single Index Query", False, f"Error: {str(e)}")
        return False


def test_multiple_indexes(splunk, index_list):
    """Test querying multiple indexes."""
    print_header(f"Test 3: Multiple Index Query - '{index_list}'")
    
    try:
        # Test fetching security logs from multiple indexes
        print(f"   Querying indexes: {index_list}")
        results = splunk.fetch_security_logs(
            index=index_list,
            minutes=1,
            limit=5
        )
        
        if results is not None:
            count = len(results)
            print_test("Multiple Index Query", True, f"Retrieved {count} events from multiple indexes")
            
            if count > 0:
                # Group by index
                index_counts = {}
                for event in results:
                    event_index = event.get('index', 'unknown')
                    index_counts[event_index] = index_counts.get(event_index, 0) + 1
                
                print(f"\n   Events by Index:")
                for idx, cnt in index_counts.items():
                    print(f"   - {idx}: {cnt} events")
            
            return True
        else:
            print_test("Multiple Index Query", False, "No results returned")
            return False
    except Exception as e:
        print_test("Multiple Index Query", False, f"Error: {str(e)}")
        return False


def test_security_logs_query(splunk, index_name):
    """Test security logs query with sourcetype filtering."""
    print_header(f"Test 4: Security Logs Query - '{index_name}'")
    
    try:
        print(f"   Querying security logs from: {index_name}")
        results = splunk.fetch_security_logs(
            index=index_name,
            minutes=1,
            limit=5
        )
        
        if results is not None:
            count = len(results)
            print_test("Security Logs Query", True, f"Retrieved {count} security events")
            
            if count > 0:
                # Group by sourcetype
                sourcetype_counts = {}
                for event in results:
                    st = event.get('sourcetype', 'unknown')
                    sourcetype_counts[st] = sourcetype_counts.get(st, 0) + 1
                
                print(f"\n   Events by Sourcetype:")
                for st, cnt in sorted(sourcetype_counts.items()):
                    print(f"   - {st}: {cnt} events")
            else:
                print(f"\n   ⚠️  No security events found in the last 1 minute")
                print(f"   This is normal if:")
                print(f"   - No Universal Forwarder is sending data")
                print(f"   - No logs match the configured sourcetypes")
                print(f"   - Index is empty")
            
            return True
        else:
            print_test("Security Logs Query", False, "No results returned")
            return False
    except Exception as e:
        print_test("Security Logs Query", False, f"Error: {str(e)}")
        return False


def test_time_ranges(splunk, index_name):
    """Test different time range queries."""
    print_header(f"Test 5: Time Range Queries - '{index_name}'")
    
    time_ranges = [
        (1, "Last 1 minute"),
    ]
    
    results = {}
    for minutes, description in time_ranges:
        try:
            print(f"   Testing: {description}")
            events = splunk.fetch_latest_logs(
                index=index_name,
                minutes=minutes,
                limit=5
            )
            count = len(events) if events else 0
            results[description] = (True, count)
            print(f"      ✅ Retrieved {count} events")
        except Exception as e:
            results[description] = (False, str(e))
            print(f"      ❌ Error: {str(e)}")
    
    return all(status for status, _ in results.values())


def test_all_time_query(splunk, index_name):
    """Test all-time query."""
    print_header(f"Test 6: All-Time Query - '{index_name}'")
    
    try:
        print(f"   Querying all existing data from: {index_name}")
        results = splunk.fetch_all_time_head(index=index_name, head=5)
        
        if results is not None:
            count = len(results)
            print_test("All-Time Query", True, f"Retrieved {count} events (limited to 5)")
            
            if count > 0:
                # Show time range
                times = [event.get('_time', '') for event in results if event.get('_time')]
                if times:
                    print(f"\n   Sample time range:")
                    print(f"   - Oldest: {times[-1]}")
                    print(f"   - Newest: {times[0]}")
            
            return True
        else:
            print_test("All-Time Query", False, "No results returned")
            return False
    except Exception as e:
        print_test("All-Time Query", False, f"Error: {str(e)}")
        return False


def test_custom_sourcetypes(splunk, index_name):
    """Test custom sourcetype filtering."""
    print_header(f"Test 7: Custom Sourcetype Filtering - '{index_name}'")
    
    try:
        # Test with custom sourcetypes
        custom_sourcetypes = ["*"]  # All sourcetypes
        print(f"   Testing with custom sourcetypes: {custom_sourcetypes}")
        
        results = splunk.fetch_security_logs(
            index=index_name,
            minutes=1,
            limit=5,
            sourcetypes=custom_sourcetypes
        )
        
        if results is not None:
            count = len(results)
            print_test("Custom Sourcetype Filtering", True, f"Retrieved {count} events")
            return True
        else:
            print_test("Custom Sourcetype Filtering", False, "No results returned")
            return False
    except Exception as e:
        print_test("Custom Sourcetype Filtering", False, f"Error: {str(e)}")
        return False


def test_universal_forwarder_data(splunk, index_name):
    """Test if data from Universal Forwarder is accessible."""
    print_header(f"Test 8: Universal Forwarder Data Access - '{index_name}'")
    
    try:
        # Query recent data (last 1 minute - typical forwarder interval)
        print(f"   Checking for recent data from Universal Forwarder...")
        results = splunk.fetch_latest_logs(
            index=index_name,
            minutes=1,
            limit=5
        )
        
        if results is not None:
            count = len(results)
            
            if count > 0:
                print_test("Universal Forwarder Data Access", True, 
                          f"✅ Found {count} recent events - Universal Forwarder is likely sending data!")
                
                # Analyze event sources
                hosts = set()
                sources = set()
                for event in results:
                    if event.get('host'):
                        hosts.add(event['host'])
                    if event.get('source'):
                        sources.add(event['source'])
                
                print(f"\n   Data Sources:")
                print(f"   - Unique hosts: {len(hosts)}")
                if hosts:
                    print(f"   - Hosts: {', '.join(list(hosts)[:5])}")
                    if len(hosts) > 5:
                        print(f"     ... and {len(hosts) - 5} more")
                print(f"   - Unique sources: {len(sources)}")
                
                return True
            else:
                print_test("Universal Forwarder Data Access", False,
                          f"⚠️  No recent events found in last 5 minutes")
                print(f"   This could mean:")
                print(f"   - Universal Forwarder is not configured")
                print(f"   - Universal Forwarder is not sending data to this index")
                print(f"   - No activity in the last 5 minutes")
                print(f"   - Check Universal Forwarder configuration and status")
                return False
        else:
            print_test("Universal Forwarder Data Access", False, "Query failed")
            return False
    except Exception as e:
        print_test("Universal Forwarder Data Access", False, f"Error: {str(e)}")
        return False


def main():
    """Main test function."""
    parser = argparse.ArgumentParser(
        description="Test Universal Forwarder integration and multiple index support"
    )
    parser.add_argument(
        "--index",
        default=None,
        help="Index to test (default: from SPLUNK_INDEX env var or '*')"
    )
    parser.add_argument(
        "--indexes",
        default=None,
        help="Comma-separated list of indexes to test (e.g., 'botsv3,main,security')"
    )
    parser.add_argument(
        "--skip-forwarder-test",
        action="store_true",
        help="Skip Universal Forwarder data access test"
    )
    
    args = parser.parse_args()
    
    # Get configuration from environment
    splunk_host = os.environ.get("SPLUNK_HOST", "localhost")
    splunk_port = os.environ.get("SPLUNK_PORT", "8089")
    splunk_username = os.environ.get("SPLUNK_USERNAME", "admin")
    splunk_password = os.environ.get("SPLUNK_PASSWORD", "")
    
    # Get index configuration
    default_index = os.environ.get("SPLUNK_INDEX", "*")
    test_index = args.index or default_index.split(",")[0]  # Use first index if multiple
    
    # Validate configuration
    if not splunk_password:
        print("❌ Error: SPLUNK_PASSWORD not set in environment variables")
        print("   Set it in .env file or export it:")
        print("   export SPLUNK_PASSWORD=your_password")
        return 1
    
    # Construct Splunk URL
    if not splunk_host.startswith("http"):
        if splunk_port in ["8000", "8001"]:
            splunk_port = "8089"
        splunk_base_url = f"https://{splunk_host}:{splunk_port}"
    else:
        splunk_base_url = f"{splunk_host}:{splunk_port}"
    
    print_header("Universal Forwarder & Multiple Index Test Suite")
    print(f"\nConfiguration:")
    print(f"  Splunk Host: {splunk_base_url}")
    print(f"  Username: {splunk_username}")
    print(f"  Test Index: {test_index}")
    if args.indexes:
        print(f"  Multiple Indexes: {args.indexes}")
    print()
    
    try:
        # Initialize Splunk connector
        print("🔌 Connecting to Splunk...")
        splunk = SplunkConnector(
            base_url=splunk_base_url,
            username=splunk_username,
            password=splunk_password
        )
        
        # Run tests
        test_results = []
        
        # Test 1: Connection
        test_results.append(("Connection", test_splunk_connection(splunk)))
        
        if not test_results[-1][1]:
            print("\n❌ Connection failed. Please check your Splunk configuration.")
            return 1
        
        # Test 2: Single index
        test_results.append(("Single Index", test_single_index(splunk, test_index)))
        
        # Test 3: Multiple indexes (if provided)
        if args.indexes:
            test_results.append(("Multiple Indexes", test_multiple_indexes(splunk, args.indexes)))
        elif "," in default_index:
            # Test with default multiple indexes if configured
            test_results.append(("Multiple Indexes", test_multiple_indexes(splunk, default_index)))
        
        # Test 4: Security logs query
        test_results.append(("Security Logs", test_security_logs_query(splunk, test_index)))
        
        # Test 5: Time ranges
        test_results.append(("Time Ranges", test_time_ranges(splunk, test_index)))
        
        # Test 6: All-time query
        test_results.append(("All-Time Query", test_all_time_query(splunk, test_index)))
        
        # Test 7: Custom sourcetypes
        test_results.append(("Custom Sourcetypes", test_custom_sourcetypes(splunk, test_index)))
        
        # Test 8: Universal Forwarder data
        if not args.skip_forwarder_test:
            test_results.append(("Universal Forwarder", test_universal_forwarder_data(splunk, test_index)))
        
        # Summary
        print_header("Test Summary")
        passed = sum(1 for _, result in test_results if result)
        total = len(test_results)
        
        for test_name, result in test_results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"  {status}: {test_name}")
        
        print(f"\nResults: {passed}/{total} tests passed")
        
        if passed == total:
            print("\n🎉 All tests passed! Your system is ready for Universal Forwarder integration.")
            return 0
        else:
            print(f"\n⚠️  {total - passed} test(s) failed. Review the output above for details.")
            return 1
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

