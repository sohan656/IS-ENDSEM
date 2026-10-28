# Ques1

def hash_function(input_string):
    hash_value = 5381

    for ch in input_string:
        # Multiply by 33 and add ASCII value
        hash_value = (hash_value * 33) + ord(ch)

        # Bitwise mixing
        hash_value ^= (hash_value >> 16)

    # Keep the hash within 32 bits
    hash_value &= 0xFFFFFFFF

    return hash_value

text = "Hello"
print(hash_function(text))

