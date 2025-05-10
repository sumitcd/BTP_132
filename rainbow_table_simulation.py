import hashlib
import itertools
import json

# Function to generate a rainbow table
def generate_rainbow_table(charset, max_length, hash_algorithm):
    rainbow_table = {}
    for length in range(1, max_length + 1):
        for combination in itertools.product(charset, repeat=length):
            password = ''.join(combination)
            hashed_password = hash_algorithm(password.encode()).hexdigest()
            rainbow_table[hashed_password] = password
    return rainbow_table

# Function to simulate an attack using the rainbow table
def rainbow_table_attack(target_hash, rainbow_table):
    return rainbow_table.get(target_hash, None)

# Example usage
if __name__ == "__main__":
    charset = "abcdefghijklmnopqrstuvwxyz"
    max_length = 5  # Adjust for demonstration purposes
    hash_algorithm = hashlib.sha256  # You can replace this with other algorithms

    print("Generating rainbow table...")
    rainbow_table = generate_rainbow_table(charset, max_length, hash_algorithm)

    # Save the rainbow table to a file for reuse
    with open("rainbow_table.json", "w") as file:
        json.dump(rainbow_table, file)

    print("Rainbow table generated and saved.")

    # Simulate an attack
    target_password = "admin"
    target_hash = hash_algorithm(target_password.encode()).hexdigest()

    print("Simulating attack...")
    result = rainbow_table_attack(target_hash, rainbow_table)

    if result:
        print(f"Password found: {result}")
    else:
        print("Password not found in the rainbow table.")
