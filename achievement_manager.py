"""
achievement_manager.py - Manages the achievement system for Bjorn.
Handles loading achievements, checking progress, and awarding achievements.
"""

import json
import os
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from logger import Logger

logger = Logger(name="achievement_manager.py", level=logging.DEBUG)

class AchievementManager:
    """
    Manages the achievement system for Bjorn.
    """

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.achievements_file = os.path.join("config", "achievements.json")
        self.achievements_data_file = os.path.join("data", "output", "achievements.json")
        self.achievements = {}
        self.unlocked_achievements = set()
        self.achievement_progress = {}
        self.last_achievement_time = 0

        # Load achievements and progress
        self.load_achievements()
        self.load_progress()

        # Initialize progress tracking
        self.initialize_progress()

        logger.info("AchievementManager initialized")

    def load_achievements(self):
        """Load achievements from the configuration file."""
        try:
            with open(self.achievements_file, 'r') as f:
                data = json.load(f)
                self.achievements = data.get('achievements', {})
                self.categories = data.get('categories', {})
                self.settings = data.get('settings', {})
            logger.info(f"Loaded {len(self.achievements)} achievements")
        except Exception as e:
            logger.error(f"Error loading achievements: {e}")
            self.achievements = {}
            self.categories = {}
            self.settings = {}

    def load_progress(self):
        """Load achievement progress from file."""
        try:
            if os.path.exists(self.achievements_data_file):
                with open(self.achievements_data_file, 'r') as f:
                    data = json.load(f)
                    self.unlocked_achievements = set(data.get('unlocked', []))
                    self.achievement_progress = data.get('progress', {})
                logger.info(f"Loaded progress: {len(self.unlocked_achievements)} unlocked achievements")
            else:
                self.unlocked_achievements = set()
                self.achievement_progress = {}
        except Exception as e:
            logger.error(f"Error loading achievement progress: {e}")
            self.unlocked_achievements = set()
            self.achievement_progress = {}

    def save_progress(self):
        """Save achievement progress to file."""
        try:
            os.makedirs(os.path.dirname(self.achievements_data_file), exist_ok=True)
            data = {
                'unlocked': list(self.unlocked_achievements),
                'progress': self.achievement_progress,
                'last_updated': datetime.now().isoformat()
            }
            with open(self.achievements_data_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug("Achievement progress saved")
        except Exception as e:
            logger.error(f"Error saving achievement progress: {e}")

    def initialize_progress(self):
        """Initialize progress tracking for all achievements."""
        for achievement_id, achievement in self.achievements.items():
            if achievement_id not in self.achievement_progress:
                self.achievement_progress[achievement_id] = {
                    'current': 0,
                    'required': achievement['requirement']['value'],
                    'completed': False
                }

    def get_current_stats(self) -> Dict[str, Any]:
        """Get current statistics for achievement checking."""
        return {
            'targets': self.shared_data.targetnbr,
            'ports': self.shared_data.portnbr,
            'vulnerabilities': self.shared_data.vulnnbr,
            'credentials': self.shared_data.crednbr,
            'zombies': self.shared_data.zombiesnbr,
            'data_stolen': self.shared_data.datanbr,
            'attacks': self.shared_data.attacksnbr,
            'wireless_cracked': self.shared_data.wirelessnbr,
            'network_control': self.calculate_network_control(),
            'stealth_attacks': self.get_stealth_attacks_count(),
            'speed_attacks': self.get_speed_attacks_count(),
            'attack_methods': self.get_attack_methods_count(),
            'first_attack': 1 if self.shared_data.attacksnbr > 0 else 0
        }

    def calculate_network_control(self) -> float:
        """Calculate network control percentage."""
        try:
            # This is a simplified calculation - you might want to enhance this
            total_targets = self.shared_data.targetnbr
            controlled_targets = self.shared_data.zombiesnbr

            if total_targets == 0:
                return 0.0

            return min(controlled_targets / total_targets, 1.0)
        except Exception:
            return 0.0

    def get_stealth_attacks_count(self) -> int:
        """Get count of stealth attacks (attacks without detection)."""
        # This is a placeholder - you might want to implement actual stealth detection
        return min(self.shared_data.attacksnbr, 10)  # Simplified for now

    def get_speed_attacks_count(self) -> int:
        """Get count of speed attacks (attacks completed quickly)."""
        # This is a placeholder - you might want to implement actual speed tracking
        return min(self.shared_data.attacksnbr, 5)  # Simplified for now

    def get_attack_methods_count(self) -> int:
        """Get count of different attack methods used."""
        # This is a placeholder - you might want to track actual attack methods
        methods = 0
        if self.shared_data.attacksnbr > 0:
            methods += 1  # At least one method used
        if self.shared_data.wirelessnbr > 0:
            methods += 1  # Wireless attacks
        if self.shared_data.crednbr > 0:
            methods += 1  # Credential attacks
        return min(methods, 3)

    def check_achievements(self):
        """Check all achievements and award any that are newly completed."""
        current_stats = self.get_current_stats()
        newly_unlocked = []

        for achievement_id, achievement in self.achievements.items():
            if achievement_id in self.unlocked_achievements:
                continue  # Already unlocked

            requirement_type = achievement['requirement']['type']
            required_value = achievement['requirement']['value']
            current_value = current_stats.get(requirement_type, 0)

            # Update progress
            if achievement_id not in self.achievement_progress:
                self.achievement_progress[achievement_id] = {
                    'current': 0,
                    'required': required_value,
                    'completed': False
                }

            self.achievement_progress[achievement_id]['current'] = current_value

            # Check if achievement is completed
            if current_value >= required_value:
                self.unlock_achievement(achievement_id, achievement)
                newly_unlocked.append(achievement_id)

        # Save progress
        if newly_unlocked:
            self.save_progress()

        return newly_unlocked

    def unlock_achievement(self, achievement_id: str, achievement: Dict[str, Any]):
        """Unlock an achievement and award rewards."""
        self.unlocked_achievements.add(achievement_id)
        self.achievement_progress[achievement_id]['completed'] = True

        # Award coins
        reward = achievement.get('reward', 0)
        self.shared_data.coinnbr += reward

        # Log achievement unlock
        logger.info(f"Achievement unlocked: {achievement['name']} - {achievement['description']} (+{reward} coins)")

        # Update display with achievement notification
        self.notify_achievement_unlock(achievement)

    def notify_achievement_unlock(self, achievement: Dict[str, Any]):
        """Notify about achievement unlock on the display."""
        current_time = time.time()
        if current_time - self.last_achievement_time > 2:  # Prevent spam
            self.last_achievement_time = current_time

            # Update Bjorn's status text to show achievement
            achievement_text = f"🏆 {achievement['name']}!"
            self.shared_data.bjornstatustext = achievement_text
            self.shared_data.bjornstatustext2 = achievement['description']

            # Update Bjorn's comment
            self.shared_data.bjornsays = f"Just unlocked: {achievement['name']}!"

            logger.info(f"Achievement notification: {achievement['name']}")

    def get_achievement_progress(self, achievement_id: str) -> Dict[str, Any]:
        """Get progress for a specific achievement."""
        if achievement_id not in self.achievements:
            return {}

        progress = self.achievement_progress.get(achievement_id, {})
        achievement = self.achievements[achievement_id]

        return {
            'id': achievement_id,
            'name': achievement['name'],
            'description': achievement['description'],
            'category': achievement['category'],
            'reward': achievement['reward'],
            'current': progress.get('current', 0),
            'required': progress.get('required', achievement['requirement']['value']),
            'completed': achievement_id in self.unlocked_achievements,
            'progress_percentage': min(100, (progress.get('current', 0) / achievement['requirement']['value']) * 100)
        }

    def get_all_achievements(self) -> List[Dict[str, Any]]:
        """Get all achievements with their progress."""
        achievements = []
        for achievement_id in self.achievements:
            achievements.append(self.get_achievement_progress(achievement_id))
        return achievements

    def get_achievements_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get achievements filtered by category."""
        achievements = []
        for achievement_id, achievement in self.achievements.items():
            if achievement.get('category') == category:
                achievements.append(self.get_achievement_progress(achievement_id))
        return achievements

    def get_unlocked_count(self) -> int:
        """Get count of unlocked achievements."""
        return len(self.unlocked_achievements)

    def get_total_count(self) -> int:
        """Get total count of achievements."""
        return len(self.achievements)

    def get_completion_percentage(self) -> float:
        """Get percentage of achievements completed."""
        if self.get_total_count() == 0:
            return 0.0
        return (self.get_unlocked_count() / self.get_total_count()) * 100

    def get_total_rewards_earned(self) -> int:
        """Get total coins earned from achievements."""
        total = 0
        for achievement_id in self.unlocked_achievements:
            if achievement_id in self.achievements:
                total += self.achievements[achievement_id].get('reward', 0)
        return total