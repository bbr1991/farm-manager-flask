# generate_charging_barcodes.py
import barcode
from barcode.writer import ImageWriter # This writer allows saving as image files
import os

def generate_cards(prefix="CHG", start_num=1, count=100, output_dir="generated_cards", code_format_digits=4):
    """
    Generates unique card codes and their corresponding barcode images.

    Args:
        prefix (str): A prefix for card codes (e.g., "CHG" for Charging).
        start_num (int): The starting number for the card sequence.
        count (int): The total number of cards to generate.
        output_dir (str): The directory where barcode images and the text file will be saved.
        code_format_digits (int): The number of digits for the numerical part of the code (e.g., 4 for 0001).
    """
    
    # Create the output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: '{output_dir}'")

    card_data_list = [] # To store all generated codes for the text file
    
    print(f"\n--- Generating {count} Charging Cards ---")
    print(f"  Prefix: '{prefix}', Starting Number: {start_num}")
    print(f"  Output Directory: '{os.path.abspath(output_dir)}'\n")

    for i in range(start_num, start_num + count):
        # Format the card code (e.g., "CHG" + "0001" = "CHG0001")
        card_code = f"{prefix}{i:0{code_format_digits}d}" 
        card_data_list.append(card_code)

        # Generate barcode image
        # Using Code128, a common and versatile barcode standard
        # The `writer=ImageWriter()` tells it to output an image.
        Code128 = barcode.get_barcode_class('code128')
        my_barcode = Code128(card_code, writer=ImageWriter())
        
        # Save the barcode as a PNG file
        # The save() method returns the full path to the generated file.
        filename = my_barcode.save(os.path.join(output_dir, card_code))
        print(f"  Generated: {card_code} -> {os.path.basename(filename)}")
        
    # Optionally save all codes to a single text file
    output_text_file = os.path.join(output_dir, "card_codes.txt")
    with open(output_text_file, "w") as f:
        for code in card_data_list:
            f.write(code + "\n")
    print(f"\nGenerated {count} barcode images and saved codes to '{os.path.basename(output_text_file)}' in '{output_dir}/'")
    print("------------------------------------------")

if __name__ == "__main__":
    # --- Example Usage ---
    
    # Scenario 1: Generate the first 50 cards
    generate_cards(prefix="CHG", start_num=1, count=50, output_dir="charging_cards_batch_1")

    # Scenario 2: Generate the next 50 cards, continuing the sequence
    # Make sure you update 'start_num' based on the last card generated in the previous batch
    # generate_cards(prefix="CHG", start_num=51, count=50, output_dir="charging_cards_batch_2")

    # Scenario 3: Generate a small test batch
    # generate_cards(prefix="TEST", start_num=1, count=5, output_dir="test_cards")