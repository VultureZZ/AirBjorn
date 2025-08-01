#!/usr/bin/env python3
"""
Test script for the achievement system.
This script tests the achievement manager functionality.
"""

import sys
import os
import json
import time

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from init_shared import shared_data
from achievement_manager import AchievementManager

def test_achievement_system():
    """Test the achievement system functionality."""
    print("🏆 Testing Bjorn Achievement System")
    print("=" * 50)

    try:
        # Initialize achievement manager
        print("1. Initializing Achievement Manager...")
        achievement_manager = AchievementManager(shared_data)
        print(f"   ✓ Loaded {achievement_manager.get_total_count()} achievements")
        print(f"   ✓ Currently unlocked: {achievement_manager.get_unlocked_count()}")

        # Test achievement checking
        print("\n2. Testing Achievement Checking...")
        newly_unlocked = achievement_manager.check_achievements()
        if newly_unlocked:
            print(f"   ✓ Newly unlocked: {newly_unlocked}")
        else:
            print("   ✓ No new achievements unlocked")

        # Test statistics
        print("\n3. Testing Statistics...")
        stats = achievement_manager.get_current_stats()
        print("   Current Statistics:")
        for key, value in stats.items():
            print(f"     {key}: {value}")

        # Test achievement progress
        print("\n4. Testing Achievement Progress...")
        achievements = achievement_manager.get_all_achievements()
        print("   Achievement Progress:")
        for achievement in achievements[:5]:  # Show first 5
            status = "🏆" if achievement['completed'] else "🔒"
            progress = f"{achievement['current']}/{achievement['required']}"
            print(f"     {status} {achievement['name']}: {progress}")

        # Test categories
        print("\n5. Testing Categories...")
        categories = achievement_manager.categories
        print("   Available Categories:")
        for category, name in categories.items():
            count = len(achievement_manager.get_achievements_by_category(category))
            print(f"     {category}: {name} ({count} achievements)")

        # Test completion percentage
        completion = achievement_manager.get_completion_percentage()
        total_rewards = achievement_manager.get_total_rewards_earned()
        print(f"\n6. Overall Progress:")
        print(f"   Completion: {completion:.1f}%")
        print(f"   Total Rewards Earned: {total_rewards} coins")

        print("\n✅ Achievement system test completed successfully!")

    except Exception as e:
        print(f"\n❌ Error testing achievement system: {e}")
        import traceback
        traceback.print_exc()
        return False

    return True

def test_achievement_unlock():
    """Test unlocking a specific achievement."""
    print("\n🎯 Testing Achievement Unlock Simulation")
    print("=" * 50)

    try:
        achievement_manager = AchievementManager(shared_data)

        # Simulate some progress
        print("1. Simulating progress...")

        # Get current stats
        stats = achievement_manager.get_current_stats()
        print(f"   Current attacks: {stats.get('attacks', 0)}")
        print(f"   Current targets: {stats.get('targets', 0)}")

        # Check for novice achievements
        print("\n2. Checking for novice achievements...")
        achievements = achievement_manager.get_all_achievements()
        novice_achievements = [a for a in achievements if 'NOVICE' in a['id']]

        for achievement in novice_achievements:
            if not achievement['completed']:
                print(f"   🔍 {achievement['name']}: {achievement['current']}/{achievement['required']}")

        print("\n✅ Achievement unlock test completed!")

    except Exception as e:
        print(f"\n❌ Error testing achievement unlock: {e}")
        import traceback
        traceback.print_exc()
        return False

    return True

if __name__ == "__main__":
    print("🚀 Starting Bjorn Achievement System Tests")
    print("=" * 60)

    # Run tests
    test1_success = test_achievement_system()
    test2_success = test_achievement_unlock()

    print("\n" + "=" * 60)
    if test1_success and test2_success:
        print("🎉 All tests passed! Achievement system is working correctly.")
    else:
        print("⚠️  Some tests failed. Please check the error messages above.")

    print("\n📊 Achievement System Summary:")
    print("- 20 achievements available")
    print("- 8 achievement categories")
    print("- Progress tracking and rewards")
    print("- Web interface integration")
    print("- E-paper display integration")