import os
import magic
import logging

# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Configure logging to store the log file in the same directory as the script
log_file_path = os.path.join(script_dir, 'file_analysis.log')
logging.basicConfig(
    filename=log_file_path, 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_file_types(file_path):
    """
    Determines the MIME type and human-readable file type of a given file using its magic number.

    Parameters:
        file_path (str): Path to the file to analyze.

    Returns:
        dict: A dictionary with 'mime_type', 'readable_type', or an error message.
    """
    try:
        # Check if file exists and is accessible
        if not os.path.isfile(file_path):
            error_message = "The specified file does not exist or is not a valid file."
            logging.info(f"File Path: {file_path}, Result: {error_message}")
            return {"error": error_message}

        # Initialize the magic object for MIME type
        mime_magic = magic.Magic(mime=True)
        human_magic = magic.Magic(mime=False)

        # Identify file types based on the magic number
        mime_type = mime_magic.from_file(file_path)
        readable_type = human_magic.from_file(file_path)

        result_message = f"MIME Type: {mime_type}, Human-Readable Type: {readable_type}"
        logging.info(f"File Path: {file_path}, Result: {result_message}")

        return {"mime_type": mime_type, "readable_type": readable_type}

    except ImportError:
        error_message = "The 'python-magic' library or 'libmagic' dependency is not installed."
        logging.error(f"File Path: {file_path}, Result: {error_message}")
        return {"error": error_message}

    except Exception as e:
        error_message = f"Unable to analyze the file. Details: {e}"
        logging.error(f"File Path: {file_path}, Result: {error_message}")
        return {"error": error_message}

# Main entry point for user interaction
if __name__ == "__main__":
    while True:
        file_path = input("Enter the full path of the file to analyze (or type 'exit' to quit): ").strip()
        
        if file_path.lower() == 'exit':
            print("Exiting the file analysis tool. Goodbye!")
            break
        
        # Analyze the file and get both formats
        result = get_file_types(file_path)

        # Display results
        if "error" in result:
            print(result["error"])
        else:
            print(f"MIME Type: {result['mime_type']}")
            print(f"Human-Readable Type: {result['readable_type']}")
