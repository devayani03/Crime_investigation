import sys
import argparse
import requests
from time import sleep
from tkinter import Tk, filedialog, Label, Text, Scrollbar, Button, Frame
from pprint import pprint

class VirusTotal_API:
    def __init__(self, apiKey):
        self.apiKey = apiKey

    def uploadFile(self, fileName):
        ''' upload file to virustotal online scanner, and receive its response message'''
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        files = {'file': open(fileName, 'rb')}
        params = {'apikey': self.apiKey}
        r = requests.post(url, data=params, files=files)

        r.raise_for_status()
        if r.headers['Content-Type'] == 'application/json':
            return r.json()['resource']
        else:
            raise Exception('Unable to locate result')

    def retrieveReport(self, resourceId):
        ''' retrieve report of an existing resource on the virustotal server '''
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': self.apiKey, 'resource': resourceId}
        while True:
            r = requests.get(url, params=params)
            r.raise_for_status()

            if r.headers['Content-Type'] == 'application/json':
                if r.json()['response_code'] == 1:
                    break
                else:
                    delay = 25
                    sleep(delay)
            else:
                raise Exception('Invalid content type')

        report = r.json()
        self.report = report
        positives = []
        for engine, result in report['scans'].items():
            if result['detected'] == True:
                positives.append(engine)
        return positives

def browse_file(api_key_label):
    file_path = filedialog.askopenfilename()
    api_key_label['text'] = file_path
    return file_path

def display_results(positives, filename):
    result_window = Tk()
    result_window.title("Scan Results")

    frame = Frame(result_window)
    frame.pack()

    scrollbar = Scrollbar(frame)
    scrollbar.pack(side='right', fill='y')

    result_text = Text(frame, wrap='word', yscrollcommand=scrollbar.set)
    result_text.insert('end', f"Scanned file: {filename}\n\n")

    if len(positives) > 0:
        result_text.insert('end', f'Positives: {len(positives)}\n')
        result_text.insert('end', "Alerts:\n")
        for alert in positives:
            result_text.insert('end', f"- {alert}\n")
    else:
        result_text.insert('end', "No threats detected.\n")

    result_text.pack(side='left', fill='both', expand=True)
    scrollbar.config(command=result_text.yview)

    result_window.mainloop()

def scan_file(api_key_label):
    file_path = api_key_label['text']

    api = VirusTotal_API(api_key)
    resource_id = api.uploadFile(file_path)

    positives = api.retrieveReport(resource_id)

    filename = file_path
    display_results(positives, filename)

if __name__ == '__main__':
    api_key = '788912950ab73ac48ec575a041351e944cda861eaf1c90f2cf38a2aad5cf2b38'  # Your API key here

    root = Tk()
    root.title("File Scanner")

    api_key_label = Label(root, text="Select a file to scan")
    api_key_label.pack()

    browse_button = Button(root, text="Browse", command=lambda: browse_file(api_key_label))
    browse_button.pack()

    scan_button = Button(root, text="Scan", command=lambda: scan_file(api_key_label))
    scan_button.pack()

    root.mainloop()
