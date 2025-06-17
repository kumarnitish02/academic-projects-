import re
import sys
import subprocess  
import csv
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QTextEdit, QFileDialog)
from bs4 import BeautifulSoup
import requests

class WebScraperApp(QWidget):
    def __init__(self):
        super().__init__()

        # Set up the GUI
        self.initUI()

    def initUI(self):
        # Window title and size
        self.setWindowTitle('Web Scraper Tool || Dev kumar || hex software ')
        self.setGeometry(100, 100, 600, 600)

        # Layout
        layout = QVBoxLayout()

        # Label and Input for URL
        self.urlLabel = QLabel('Enter Website URL:', self)
        self.urlLabel = QLabel('like https://example.in', self)
        self.urlInput = QLineEdit(self)

        # Button to scrape data
        self.scrapeButton = QPushButton('Scrape Data', self)
        self.scrapeButton.clicked.connect(self.scrapeData)

        # Text area to display the scraped data
        self.outputArea = QTextEdit(self)
        self.outputArea.setReadOnly(True)

        # Save button
        self.saveButton = QPushButton('Save to CSV', self)
        self.saveButton.clicked.connect(self.saveToCSV)

        # Add widgets to layout
        layout.addWidget(self.urlLabel)
        layout.addWidget(self.urlInput)
        layout.addWidget(self.scrapeButton)
        layout.addWidget(self.outputArea)
        layout.addWidget(self.saveButton)

        # Set layout to the window
        self.setLayout(layout)

    def scrapeData(self):
        url = self.urlInput.text()
        if not url:
            self.outputArea.setText("Please enter a valid URL.")
            return

        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract author
            author = self.extract_author(soup)

            # Extract emails
            emails = self.extract_emails(response.text)

            # Extract phone numbers
            phone_numbers = self.extract_phone_numbers(response.text)

            # Extract embedded links and categorize
            embedded_links = self.extract_links(soup)

            # Extract address
            address = self.extract_address(soup)

            # Extract programming language and web server info
            programming_language, web_server = self.extract_headers(url)

            # Extract input fields
            input_fields = self.extract_input_fields(soup)

            # Extract file upload mechanisms
            file_uploads = self.extract_file_uploads(soup)

            # Extract open ports using nmap
            open_ports = self.get_open_ports(url)

            # Display the scraped data in a structured format
            self.outputArea.clear()

            self.outputArea.append("<b>Author Information</b>")
            self.outputArea.append(f"Author: {author}\n")

            self.outputArea.append("<b>Contact Information</b>")
            self.outputArea.append(f"Emails Found: {len(emails)}")
            self.outputArea.append(f"Emails: {', '.join(emails)}")
            self.outputArea.append(f"Phone Numbers Found: {len(phone_numbers)}")
            self.outputArea.append(f"Phone Numbers: {', '.join(phone_numbers)}\n")

            self.outputArea.append("<b>Embedded Links</b>")
            self.outputArea.append(f"Internal Links Found: {len(embedded_links['internal_links'])}")
            self.outputArea.append("Internal Links:")
            self.outputArea.append('\n'.join(embedded_links['internal_links'] if embedded_links['internal_links'] else ['Not found']))

            self.outputArea.append("\nExternal Links Found: {}".format(len(embedded_links['external_links'])))
            self.outputArea.append("External Links:")
            self.outputArea.append('\n'.join(embedded_links['external_links'] if embedded_links['external_links'] else ['Not found']))

            self.outputArea.append("\n<b>Address Information</b>")
            self.outputArea.append(f"Address: {address if address else 'Not found'}")

            self.outputArea.append("\n<b>Technical Details</b>")
            self.outputArea.append(f"Programming Language: {programming_language}")
            self.outputArea.append(f"Web Server: {web_server}")
            self.outputArea.append(f"Open Ports Found: {len(open_ports)}")
            self.outputArea.append(f"Open Ports: {', '.join(open_ports) if open_ports else 'Not found'}")

            self.outputArea.append("\n<b>Form Information</b>")
            self.outputArea.append(f"Input Fields Found: {len(input_fields)}")
            self.outputArea.append(f"Input Fields: {', '.join([field.get('name', 'Unnamed') for field in input_fields]) if input_fields else 'Not found'}")
            self.outputArea.append(f"File Upload Mechanisms Found: {len(file_uploads)}")
            self.outputArea.append(f"File Upload Mechanisms: {', '.join(['Yes' for field in file_uploads]) if file_uploads else 'No'}")

            # Store the data for saving later
            self.data = {
                'Author': author,
                'Emails': emails,
                'Phone Numbers': phone_numbers,
                'Internal Links': embedded_links['internal_links'],
                'External Links': embedded_links['external_links'],
                'Address': address,
                'Programming Language': programming_language,
                'Web Server': web_server,
                'Open Ports': open_ports,
                'Input Fields': input_fields,
                'File Upload Mechanisms': file_uploads
            }

        except Exception as e:
            self.outputArea.setText(f"Error occurred: {str(e)}")

    def extract_author(self, soup):
        """Extract the author's name from the page metadata."""
        author = None
        # Look for meta author tag
        meta_author = soup.find('meta', {'name': 'author'})
        if meta_author:
            author = meta_author.get('content')
        # Check for author name in visible content
        author_tag = soup.find(['span', 'p'], class_=re.compile(r'author', re.I))
        if author_tag:
            author = author_tag.text.strip()
        return author if author else 'Not found'

    def extract_emails(self, text):
        """Extract email addresses using a regular expression."""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, text)
        return emails if emails else ['Not found']

    def extract_phone_numbers(self, text):
        """Extract phone numbers using a regular expression."""
        phone_pattern = r'\+?\d[\d -]{8,12}\d'
        phone_numbers = re.findall(phone_pattern, text)
        return phone_numbers if phone_numbers else ['Not found']

    def extract_links(self, soup):
        """Extract all embedded links from the page and categorize them."""
        internal_links = []
        external_links = []
        base_url = self.urlInput.text()

        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if href.startswith('http'):  # External link
                external_links.append(href)
            else:  # Internal link
                if not href.startswith('/'):
                    internal_links.append(href)
                else:
                    internal_links.append(base_url + href)

        return {'internal_links': list(set(internal_links)), 'external_links': list(set(external_links))}

    def extract_address(self, soup):
        """Try to extract an address from the page content."""
        address_tag = soup.find('address')
        if address_tag:
            return address_tag.text.strip()
        address_div = soup.find('div', class_=re.compile(r'address', re.I))
        if address_div:
            return address_div.text.strip()
        return None

    def extract_headers(self, url):
        """Extract headers from the HTTP response to detect programming language and web server."""
        try:
            response = requests.head(url)
            headers = response.headers
            programming_language = headers.get('X-Powered-By', 'Not found')
            web_server = headers.get('Server', 'Not found')
            return programming_language, web_server
        except Exception as e:
            return 'Not found', 'Not found'

    def extract_input_fields(self, soup):
        """Extract all input fields on the webpage."""
        return soup.find_all('input')

    def extract_file_uploads(self, soup):
        """Check for file upload mechanisms on the page."""
        return soup.find_all('input', {'type': 'file'})

    def get_open_ports(self, url):
        """Use nmap to scan for open ports on the target website."""
        try:
            domain = url.split("//")[-1].split("/")[0]
            result = subprocess.check_output(['nmap', '-p', '80,443', domain])
            open_ports = re.findall(r'(\d+)/open', result.decode('utf-8'))
            return open_ports
        except Exception as e:
            return ['Error scanning ports']

    def saveToCSV(self):
        if not hasattr(self, 'data'):
            self.outputArea.setText("No data to save. Please scrape data first.")
            return

        # Ask the user for a file path to save the CSV
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save CSV File", "", "CSV Files (*.csv);;All Files (*)", options=options)

        if file_path:
            # Save the scraped data to CSV
            with open(file_path, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                # Write headers
                writer.writerow(['Field', 'Value'])
                for key, value in self.data.items():
                    writer.writerow([key, ', '.join(value) if isinstance(value, list) else value])

            self.outputArea.append(f"Data saved successfully to {file_path}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    scraper = WebScraperApp()
    scraper.show()
    sys.exit(app.exec_())
