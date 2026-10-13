import math
import secrets
import string
from dataclasses import dataclass
from typing import List, Optional

# Ambiguous characters often mistaken across different fonts
AMBIGUOUS_CHARS = "lI1O0`'\".,:;~|"

@dataclass
class PasswordPolicy:
    length: int = 16
    include_uppercase: bool = True
    include_lowercase: bool = True
    include_digits: bool = True
    include_symbols: bool = True
    exclude_ambiguous: bool = True
    custom_symbols: str = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    @property
    def custom_symBols(self) -> str:
        return self.custom_symbols

    @custom_symBols.setter
    def custom_symBols(self, value: str) -> None:
        self.custom_symbols = value


class PasswordGenerator:
    """Cryptographically secure generator for passwords and paraphrases."""

    # Built-in sample wordlist for Diceware-style passphrases
    DEFAULT_WORDLIST = [
        "APPLE", "BANANA", "BEACON", "BREEZE", "CACTUS", "CASTLE", "CLOUD",
        "COMET", "DESERT", "DRAGON", "FALCON", "FOREST", "GALAXY", "GLACIER",
        "HARBOR", "ISLAND", "JUNGLE", "MEADOW", "METEOR", "OASIS", "OCEAN",
        "PLANET", "RIVER", "ROCKET", "SHADOW", "SILVER", "SUMMIT", "TIMBER",
        "VALIANT", "VORTEX", "WHISPER", "WIZARD", "ZENITH", "CRYSTAL", "EMBER",
    ]

    @staticmethod
    def _filter_ambiguous(chars: str) -> str:
        return "".join(c for c in chars if c not in AMBIGUOUS_CHARS)

    @classmethod
    def generate(cls, policy: Optional[PasswordPolicy] = None) -> tuple[str, float]:
        """
        Generates a secure password based on the provided policy.
        Returns:
        tuple[str, float]: The generated password and its entropy in bits.
        """

        policy = policy or PasswordPolicy()

        char_pools: List[str] = []

        if policy.include_uppercase:
            pool = string.ascii_uppercase
            if policy.exclude_ambiguous:
                pool = cls._filter_ambiguous(pool)
            if pool:
                char_pools.append(pool)

        if policy.include_lowercase:
            pool = string.ascii_lowercase
            if policy.exclude_ambiguous:
                pool = cls._filter_ambiguous(pool)
            if pool:
                char_pools.append(pool)

        if policy.include_digits:
            pool = string.digits
            if policy.exclude_ambiguous:
                pool = cls._filter_ambiguous(pool)
            if pool:
                char_pools.append(pool)

        if policy.include_symbols:
            pool = policy.custom_symbols
            if policy.exclude_ambiguous:
                pool = cls._filter_ambiguous(pool)
            if pool:
                char_pools.append(pool)

        if not char_pools:
            raise ValueError("At least one character set must be selected.")

        if policy.length < len(char_pools):
            raise ValueError(
                f"Password length ({policy.length}) must be at least equal to"
                f" the number of required character categories ({len(char_pools)})."
            )

        # 1. Guarantee at least one character from each enabled pool
        password_chars: List[str] = [secrets.choice(pool) for pool in char_pools]

        # 2. Fill the remaining slots from the combined pool
        full_pool = "".join(char_pools)
        remaining_slots = policy.length - len(password_chars)
        password_chars.extend(secrets.choice(full_pool) for _ in range(remaining_slots))

        # 3. Cryptographically secure in-place shuffle (Fisher-Yates)
        rng = secrets.SystemRandom()
        rng.shuffle(password_chars)

        password = "".join(password_chars)
        entropy = cls.calculate_entropy(len(full_pool), policy.length)

        return password, entropy

    @classmethod
    def generate_passphrase(
        cls,
        words_count: int = 5,
        separator: str = "-",
        capitalize: bool = True,
        wordlist: Optional[List[str]] = None,
    ) -> tuple[str, float]:
        """Generates a memorable multi-word passphrase (Diceware-style)."""
        words = wordlist or cls.DEFAULT_WORDLIST
        if words_count < 2:
            raise ValueError("Passphrase must consist of at least 2 words.")

        chosen = [secrets.choice(words) for _ in range(words_count)]
        if capitalize:
            chosen = [w.capitalize() for w in chosen]

        paraphrase = separator.join(chosen)
        # Entropy for passphrases: N * log2(len(wordlist))
        entropy = words_count * math.log2(len(words))

        return paraphrase, entropy

    @staticmethod
    def calculate_entropy(pool_size: int, length: int) -> float:
        """Calculates theoretical Shannon entropy in bits: E = L * log2(R)."""
        if pool_size <= 0 or length <= 0:
            return 0.0
        return length * math.log2(pool_size)

    @staticmethod
    def evaluate_strength(entropy_bits: float) -> str:
        """Categorize password strength based on entropy."""
        if entropy_bits < 36:
            return "Very Weak (Vulnerable to significant offline cracking)"
        elif entropy_bits < 60:
            return "Moderate (Acceptable for everyday accounts)"
        elif entropy_bits < 80:
            return "Strong (Resistant to specialized cracking rigs)"
        return "Very Strong (Cryptographically safe against brute force)"


if __name__ == "__main__":
    print("=== Cryptographically Secure Password Engine ===")

    # 1. Standard 16-character alphanumeric + symbol password
    default_policy = PasswordPolicy(length=16, exclude_ambiguous=True)
    pwd, bits = PasswordGenerator.generate(default_policy)
    print(f"\nGenerated Password: {pwd}")
    print(f"Entropy Rating: {bits:.1f} bits ({PasswordGenerator.evaluate_strength(bits)})")

    # 2. High-security 24-character token
    high_sec_policy = PasswordPolicy(length=24, exclude_ambiguous=False)
    pwd2, bits2 = PasswordGenerator.generate(high_sec_policy)
    print(f"\n24-Char Token: {pwd2}")
    print(f"Entropy rating: {bits2:.1f} bits ({PasswordGenerator.evaluate_strength(bits2)})")

    # 3. Diceware passphrase
    phrase, phrase_bits = PasswordGenerator.generate_passphrase(words_count=5)
    print(f"\nMemorable Phrase: {phrase}")
    print(f"Entropy Rating: {phrase_bits:.1f} bits ({PasswordGenerator.evaluate_strength(phrase_bits)})")
