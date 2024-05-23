import tkinter as tk

# Create the main window
root = tk.Tk()
root.title("Scan Tool")
root.geometry("300x150")  # Set the window size

# Set the background color
root.configure(background="#f0f0f0")  # Light gray

# Create a frame to hold the input field and button
frame = tk.Frame(root, bg="#f0f0f0")
frame.pack(pady=20)  # Add some padding around the frame

# Create the input field
input_field = tk.Entry(frame, width=30, font=("Helvetica", 14))
input_field.pack(pady=10)  # Add some padding around the input field

# Create the "Scan" button
scan_button = tk.Button(frame, text="Scan", font=("Helvetica", 14, "bold"), bg="#4CAF50", fg="white")
scan_button.pack(pady=10)  # Add some padding around the button

# Set the focus to the input field
input_field.focus()

# Run the application
root.mainloop()



# i = Interface(create)
# i.run()