import unittest
import tkinter as tk
from tkinter import Entry
from unittest.mock import patch
from io import StringIO
from mapper import PortScannerGUI  # Assuming your GUI class is in port_scanner_gui.py

class TestPortScannerGUI(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.app = PortScannerGUI(self.root)

    def tearDown(self):
        self.root.destroy()

    @patch.object(Entry, 'get')
    def test_start_scan_empty_host(self, mock_entry_get):
        mock_entry_get.return_value = ""
        with self.assertRaises(tk.TclError):
            self.app.start_scan()

    @patch.object(tk.messagebox, 'showerror')
    @patch.object(tk.Entry, 'get')
    def test_start_scan_invalid_host(self, mock_entry_get, mock_showerror):
        mock_entry_get.return_value = "invalidhost"
        self.app.start_scan()
        mock_showerror.assert_called_once_with("Error", "Cannot resolve or connect to the host")

    # Add more test cases as needed

if __name__ == '__main__':
    unittest.main()
