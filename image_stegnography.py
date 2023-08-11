import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cv2 import imread, imwrite
import os


class FileError(Exception):
    pass


class DataError(Exception):
    pass


class PasswordError(Exception):
    pass


def str2bin(string):
    return ''.join((bin(ord(i))[2:]).zfill(7) for i in string)


def bin2str(string):
    return ''.join(chr(int(string[i:i + 7], 2)) for i in range(len(string))[::7])


def xor_encrypt_decrypt(string, password):
    encrypted = ''
    for i, char in enumerate(string):
        key_char = password[i % len(password)]
        encrypted += chr(ord(char) ^ ord(key_char))
    return encrypted


def encode(input_filepath, text, output_filename, password=None, progressBar=None):
    if password is None:
        password = ""  # Set an empty password if it's not provide
        
    elif len(password) < 8:
        messagebox.showerror("Password Error", "Password should be at least 8 characters long.")
        pass

    else:
        data = xor_encrypt_decrypt(text, password)  # Encrypt the data with XOR
    data_length = bin(len(data))[2:].zfill(32)
    bin_data = iter(data_length + str2bin(data))
    img = imread(input_filepath, 1)

    if img is None:
        raise FileError("The image file '{}' is inaccessible".format(input_filepath))

    height, width = img.shape[0], img.shape[1]
    encoding_capacity = height * width * 3
    total_bits = 32 + len(data) * 7

    if total_bits > encoding_capacity:
        raise DataError("The data size is too big to fit in this image!")

    completed = False
    modified_bits = 0
    progress = 0
    progress_fraction = 1 / total_bits

    try:
        for i in range(height):
            for j in range(width):
                pixel = img[i, j]
                for k in range(3):
                    try:
                        x = next(bin_data)
                    except StopIteration:
                        completed = True
                        break
                    if x == '0' and pixel[k] % 2 == 1:
                        pixel[k] -= 1
                        modified_bits += 1
                    elif x == '1' and pixel[k] % 2 == 0:
                        pixel[k] += 1
                        modified_bits += 1
                    if progressBar is not None:  # If progress bar object is passed
                        progress += progress_fraction
                        progressBar.setValue(progress * 100)
                if completed:
                    break
            if completed:
                break
    except Exception as e:
        raise DataError("An error occurred while encoding the data: {}".format(str(e)))

    # Save the output image with the .png extension
    output_filepath = output_filename + ".png"
    written = imwrite(output_filepath, img)
    if not written:
        raise FileError("Failed to write image '{}'".format(output_filepath))

    loss_percentage = (modified_bits / encoding_capacity) * 100
    return loss_percentage



def decode(input_filepath, password=None, progressBar=None):
    if password is None:
        password = ""  # Set an empty password if it's not provided

    elif len(password) < 8:
        messagebox.showerror("Password Error", "Password should be at least 8 characters long.")
        pass

    else:
        result, extracted_bits, completed, number_of_bits = '', 0, False, None
    img = imread(input_filepath)

    if img is None:
        raise FileError("The image file '{}' is inaccessible".format(input_filepath))

    height, width = img.shape[0], img.shape[1]
    for i in range(height):
        for j in range(width):
            for k in img[i, j]:
                result += str(k % 2)
                extracted_bits += 1
                if progressBar is not None and number_of_bits is not None:  # If progress bar object is passed
                    progressBar.setValue(100 * (extracted_bits / number_of_bits))
                if extracted_bits == 32 and number_of_bits is None:  # If the first 32 bits are extracted, it is our data size. Now extract the original data
                    number_of_bits = int(result, 2) * 7
                    result = ''
                    extracted_bits = 0
                elif extracted_bits == number_of_bits:
                    completed = True
                    break
            if completed:
                break
        if completed:
            break
    if number_of_bits is None:
        raise DataError("No data found in the image")

    try:
        return xor_encrypt_decrypt(bin2str(result), password)
    except Exception as e:
        raise PasswordError("An error occurred while decrypting the data: {}".format(str(e)))



def open_file(entry_widget):
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png")])
    entry_widget.delete(0, tk.END)
    entry_widget.insert(tk.END, file_path)


def save_file(entry_widget):
    file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if file_path.lower().endswith(".png.png"):
        file_path = file_path[:-4]  # Remove the extra .png extension if present
    entry_widget.delete(0, tk.END)
    entry_widget.insert(tk.END, file_path)





def encode_button_click():
    input_filepath = input_file_entry.get()
    text = secret_data_entry.get()
    password = password_entry.get()
    output_filename = output_file_entry.get()

    try:
        if not input_filepath or not text or not output_filename:
            messagebox.showerror("Error", "Please fill in all the required fields.")
            return

        if not input_filepath.lower().endswith('.png'):
            img = imread(input_filepath)
            output_temp_file = "temp.png"
            imwrite(output_temp_file, img)
            loss = encode(output_temp_file, text, output_filename, password)
            os.remove(output_temp_file)
        else:
            loss = encode(input_filepath, text, output_filename, password)

        messagebox.showinfo("Success", f"Encoded Successfully!\nImage Data Loss = {loss:.5f}%")
    except FileError as fe:
        messagebox.showerror("File Error", str(fe))
    except DataError as de:
        messagebox.showerror("Data Error", str(de))
    except PasswordError:
        messagebox.showerror("Password Error", "Password should be at least 8 characters long.")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")


def decode_button_click():
    input_filepath = input_file_entry.get()
    password = password_entry.get()

    try:
        if not input_filepath:
            messagebox.showerror("Error", "Please select an input file for decoding.")
            return

        data = decode(input_filepath, password)
        messagebox.showinfo("Decrypted Data", f"Decrypted data:\n{data}")
    except FileError as fe:
        messagebox.showerror("File Error", str(fe))
    except DataError as de:
        messagebox.showerror("Data Error", str(de))
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")


def decrypt_button_click():
    global decrypt_file_entry, decrypt_password_entry
    input_filepath = decrypt_file_entry.get()
    password = decrypt_password_entry.get()

    try:
        if not input_filepath:
            messagebox.showerror("Error", "Please select an input file for decryption.")
            return

        data = decode(input_filepath, password)
        messagebox.showinfo("Decrypted Data", f"Decrypted data:\n{data}")
    except FileError as fe:
        messagebox.showerror("File Error", str(fe))
    except DataError as de:
        messagebox.showerror("Data Error", str(de))
    except PasswordError:
        messagebox.showerror("Password Error", "Incorrect password.")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")


def on_new():
    pass

def on_open():
    pass

def on_save():
    pass

def on_exit():
    root.quit()

def on_toggle_view():
    pass

def open_file(entry_widget):
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png")])
    entry_widget.delete(0, tk.END)
    entry_widget.insert(tk.END, file_path)

def save_file(entry_widget):
    file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
    if file_path.lower().endswith(".png.png"):
        file_path = file_path[:-4]  # Remove the extra .png extension if present
    entry_widget.delete(0, tk.END)
    entry_widget.insert(tk.END, file_path)


root = tk.Tk()
root.title("Image Steganography Tool")

# Create and set the style for the ttk widgets
style = ttk.Style(root)
style.theme_use("clam")

decrypt_file_entry = None
decrypt_password_entry = None


def create_encode_section():
    encode_frame = ttk.LabelFrame(root, text="Encode Section", padding="10")
    encode_frame.grid(row=1, column=0, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))


def create_decode_section():
    decode_frame = ttk.LabelFrame(root, text="Decode Section", padding="10")
    decode_frame.grid(row=2, column=0, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))

def create_decrypt_section():
    global decrypt_file_entry, decrypt_password_entry
    decrypt_frame = ttk.LabelFrame(root, text="Decrypt Section", padding="10")
    decrypt_frame.grid(row=3, column=0, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))

    # Input file for decryption
    decrypt_file_label = ttk.Label(decrypt_frame, text="Input Image for Decryption:")
    decrypt_file_label.grid(row=0, column=0, sticky=tk.W)

    decrypt_file_entry = ttk.Entry(decrypt_frame, width=40)
    decrypt_file_entry.grid(row=0, column=1, padx=(5, 0), sticky=(tk.W, tk.E))

    decrypt_file_button = ttk.Button(decrypt_frame, text="Open", command=lambda: open_file(decrypt_file_entry))
    decrypt_file_button.grid(row=0, column=2, padx=(5, 0))

    # Password for decryption
    decrypt_password_label = ttk.Label(decrypt_frame, text="Password for Decryption:")
    decrypt_password_label.grid(row=1, column=0, sticky=tk.W)

    decrypt_password_entry = ttk.Entry(decrypt_frame, width=40, show="*")
    decrypt_password_entry.grid(row=1, column=1, padx=(5, 0), sticky=(tk.W, tk.E))

    # Decrypt button
    decrypt_button = ttk.Button(decrypt_frame, text="Decrypt", command=decrypt_button_click)
    decrypt_button.grid(row=2, column=0, pady=10, sticky=tk.W)

    # Clear Button for Decrypt Section
    clear_decrypt_button = ttk.Button(decrypt_frame, text="Clear", command=clear_decrypt_fields)
    clear_decrypt_button.grid(row=2, column=1, pady=10, padx=(5, 0))

    # Set column weights to expand on resizing
    decrypt_frame.columnconfigure(1, weight=1)

def clear_input_fields():
    input_file_entry.delete(0, tk.END)
    secret_data_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    output_file_entry.delete(0, tk.END)


def clear_decrypt_fields():
    decrypt_file_entry.delete(0, tk.END)
    decrypt_password_entry.delete(0, tk.END)


# Main Frame
main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Input file
input_file_label = ttk.Label(main_frame, text="Input Image:")
input_file_label.grid(row=0, column=0, sticky=tk.W)

input_file_entry = ttk.Entry(main_frame, width=40)
input_file_entry.grid(row=0, column=1, padx=(5, 0), sticky=(tk.W, tk.E))

input_file_button = ttk.Button(main_frame, text="Open", command=lambda: open_file(input_file_entry))
input_file_button.grid(row=0, column=2, padx=(5, 0))

# Secret data
secret_data_label = ttk.Label(main_frame, text="Secret Data:")
secret_data_label.grid(row=1, column=0, sticky=tk.W)

secret_data_entry = ttk.Entry(main_frame, width=40)
secret_data_entry.grid(row=1, column=1, padx=(5, 0), sticky=(tk.W, tk.E))

# Password
password_label = ttk.Label(main_frame, text="Password:")
password_label.grid(row=2, column=0, sticky=tk.W)

password_entry = ttk.Entry(main_frame, width=40, show="*")
password_entry.grid(row=2, column=1, padx=(5, 0), sticky=(tk.W, tk.E))

# Output file
output_file_label = ttk.Label(main_frame, text="Output Image:")
output_file_label.grid(row=3, column=0, sticky=tk.W)

output_file_entry = ttk.Entry(main_frame, width=40)
output_file_entry.grid(row=3, column=1, padx=(5, 0), sticky=(tk.W, tk.E))

output_file_button = ttk.Button(main_frame, text="Save", command=lambda: save_file(output_file_entry))
output_file_button.grid(row=3, column=2, padx=(5, 0))

# Buttons
encode_button = ttk.Button(main_frame, text="Encrypt", command=encode_button_click)
encode_button.grid(row=4, column=0, pady=10, sticky=tk.W)

# Set column weights to expand on resizing
main_frame.columnconfigure(1, weight=1)

# Create Encode, Decode, and Decrypt Sections
create_encode_section()
create_decode_section()
create_decrypt_section()

# Clear Button
clear_button = ttk.Button(main_frame, text="Clear", command=clear_input_fields)
clear_button.grid(row=5, column=0, columnspan=3, pady=10)

# Add Menu Bar
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

# File Menu
file_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="File", menu=file_menu)

file_menu.add_command(label="New", command=on_new)
file_menu.add_command(label="Open", command=on_open)
file_menu.add_command(label="Save", command=on_save)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=on_exit)

# View Menu
view_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="View", menu=view_menu)

view_menu.add_command(label="Toggle View", command=on_toggle_view)

# Main loop
root.mainloop()


#Real code