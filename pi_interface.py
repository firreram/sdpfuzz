import serial
import os
import time

def send_char_to_pi(char_to_send='a', port='/dev/ttyACM0', baudrate=115200, timeout=2):
    # Check if port exists
    if not os.path.exists(port):
        print(f"No device found at {port}. Check connection and port.")
        return False
    
    print(f"Attempting to connect to {port} at {baudrate} baud")
    
    try:
        # Open serial connection
        with serial.Serial(port, baudrate, timeout=timeout) as ser:
            print("Serial connection established")
            time.sleep(1)  # Increased to ensure MicroPython is ready
            ser.write((char_to_send + '\n').encode('utf-8'))  # Send character with newline
            
            # Wait for response
            response = ser.read(100).decode('utf-8', errors='ignore')  # Read up to 100 bytes
            if response:
                print(f"Received response: {repr(response)}")
                return True
            else:
                print("No response received from Raspberry Pi")
                return False
                
    except serial.SerialException as e:
        print(f"Serial error: {str(e)}. Check port permissions or connection.")
        return False
    except AttributeError as e:
        print(f"Attribute error: {str(e)}. Ensure 'pyserial' is installed correctly.")
        return False
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return False

# Example usage
if __name__ == "__main__":
    result = send_char_to_pi('a')
    print(f"Operation {'successful' if result else 'failed'}")