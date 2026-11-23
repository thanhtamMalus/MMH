from collections import Counter

# Known English letter frequencies (from most frequent to least frequent)
english_frequencies = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'

cipher_text = ("✦✩◈◈◍ ◕●⊟⊟◆◈ ◔○ ✩ ○◆◈◔◆○ ●◉ ○◆∆◆◇ ⊞✦◔⊠◓◈◆◇'○ ◉✩◇⊟✩○◍ ◇●∆◆⊠○ ⊡◈◔⊟⊟◆◇ ◑◍ ◑◈◔⊟◔○✦ ✩★⊟✦●◈ ◎. ◐. ◈●⊡⊠◔◇□. ⊟✦◆ ◇●∆◆⊠○ ⊞✦◈●◇◔⊞⊠◆ ⊟✦◆ ⊠◔∆◆○ ●◉ ✩ ◍●★◇□ ⊡◔✧✩◈◓, ✦✩◈◈◍ ◕●⊟⊟◆◈, ✩◇◓ ✦◔○ ◉◈◔◆◇◓○, ◈●◇ ⊡◆✩○⊠◆◍ ✩◇◓ ✦◆◈✫◔●◇◆ □◈✩◇□◆◈, ✩⊠⊠ ●◉ ⊡✦●✫ ✩◈◆ ○⊟★◓◆◇⊟○ ✩⊟ ✦●□⊡✩◈⊟○ ○⊞✦●●⊠ ●◉ ⊡◔⊟⊞✦⊞◈✩◉⊟ ✩◇◓ ⊡◔✧✩◈◓◈◍. ⊟✦◆ ✫✩◔◇ ○⊟●◈◍ ✩◈⊞ ⊞●◇⊞◆◈◇○ ✦✩◈◈◍'○ ⊞●◇◉⊠◔⊞⊟ ⊡◔⊟✦ ⊠●◈◓ ∆●⊠◓◆✫●◈⊟, ✩ ◓✩◈◐ ⊡◔✧✩◈◓ ⊡✦● ◔◇⊟◆◇◓○ ⊟● ◑◆⊞●✫◆ ◔✫✫●◈⊟✩⊠, ●∆◆◈⊟✦◈●⊡ ⊟✦◆ ⊡◔✧✩◈◓ □●∆◆◈◇◔◇□ ◑●◓◍ ◐◇●⊡◇ ✩○ ⊟✦◆ ✫◔◇◔○⊟◈◍ ●◉ ✫✩□◔⊞, ✩◇◓ ○★◑◎★□✩⊟◆ ✩⊠⊠ ⊡◔✧✩◈◓○ ✩◇◓ ◇●◇-✫✩□◔⊞✩⊠ ◕◆●◕⊠◆, ◐◇●⊡◇ ◔◇-★◇◔∆◆◈○◆ ✩○ ✫★□□⊠◆○.⊟✦◆ ○◆◈◔◆○ ⊡✩○ ●◈◔□◔◇✩⊠⊠◍ ◕★◑⊠◔○✦◆◓ ◔◇ ◆◇□⊠◔○✦ ◑◍ ◑⊠●●✫○◑★◈◍ ◔◇ ⊟✦◆ ★◇◔⊟◆◓ ◐◔◇□◓●✫ ✩◇◓ ○⊞✦●⊠✩○⊟◔⊞ ◕◈◆○○ ◔◇ ⊟✦◆ ★◇◔⊟◆◓ ○⊟✩⊟◆○. ✩ ○◆◈◔◆○ ●◉ ✫✩◇◍ □◆◇◈◆○, ◔◇⊞⊠★◓◔◇□ ◉✩◇⊟✩○◍, ◓◈✩✫✩, ⊞●✫◔◇□-●◉-✩□◆ ◉◔⊞⊟◔●◇, ✩◇◓ ⊟✦◆ ◑◈◔⊟◔○✦ ○⊞✦●●⊠ ○⊟●◈◍ (⊡✦◔⊞✦ ◔◇⊞⊠★◓◆○ ◆⊠◆✫◆◇⊟○ ●◉ ✫◍○⊟◆◈◍, ⊟✦◈◔⊠⊠◆◈, ✩◓∆◆◇⊟★◈◆, ✦●◈◈●◈, ✩◇◓ ◈●✫✩◇⊞◆), ⊟✦◆ ⊡●◈⊠◓ ●◉ ✦✩◈◈◍ ◕●⊟⊟◆◈ ◆✪◕⊠●◈◆○ ◇★✫◆◈●★○ ⊟✦◆✫◆○ ✩◇◓ ◔◇⊞⊠★◓◆○ ✫✩◇◍ ⊞★⊠⊟★◈✩⊠ ✫◆✩◇◔◇□○ ✩◇◓ ◈◆◉◆◈◆◇⊞◆○. ✫✩◎●◈ ⊟✦◆✫◆○ ◔◇ ⊟✦◆ ○◆◈◔◆○ ◔◇⊞⊠★◓◆ ◕◈◆◎★◓◔⊞◆, ⊞●◈◈★◕⊟◔●◇, ✫✩◓◇◆○○, ⊠●∆◆, ✩◇◓ ◓◆✩⊟✦.")

# Count symbol frequencies in the ciphertext (ignore letters/numbers/space)
symbols = [ch for ch in cipher_text if not ch.isalnum() and ch not in " ,.'\"-–—\n"]
cipher_counts = Counter(symbols)

# Sort the ciphertext symbols by frequency (most frequent first)
sorted_cipher = ''.join([item[0] for item in cipher_counts.most_common()])

# Create an initial mapping from ciphertext symbols to the English frequency order
mapping = {}
for i, sym in enumerate(sorted_cipher):
    if i < len(english_frequencies):
        mapping[sym] = english_frequencies[i]
    else:
        mapping[sym] = sym  # fallback if more than 26 symbols

# Optional manual adjustments to improve decryption quality
# Ví dụ bạn chỉnh tay ở đây:
mapping["✩"] = "A"


def print_key_mapping_table(mapping, sorted_cipher):
    """
    Displays the key mapping in a table format:
    
    Cipher: ◔  ◆  ●  □  ⊟ ...
    Plain : T  H  E  A  O ...
    """
    row1 = "Cipher: " + " ".join(f"{sym:2}" for sym in sorted_cipher)
    row2 = "Plain : " + " ".join(f"{mapping[sym]:2}" for sym in sorted_cipher)
    print(row1)
    print(row2)

# Display the final mapping using the desired table format
print_key_mapping_table(mapping, sorted_cipher)

# Decrypt the ciphertext using the mapping
decrypted_text = []
for char in cipher_text:
    if char in mapping:
        decrypted_text.append(mapping.get(char, char))
    else:
        decrypted_text.append(char)
decrypted_text = ''.join(decrypted_text)

print("\nDecrypted Text:")
print(decrypted_text)
