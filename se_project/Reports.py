import os
import time
import datetime

import reportlab.lib.enums as e
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak, Table, TableStyle
from reportlab.pdfgen import canvas
from reportlab.graphics.charts.linecharts import HorizontalLineChart
from reportlab.graphics.shapes import Drawing
import Verification


class PageNumCanvas(canvas.Canvas):
  

    # ----------------------------------------------------------------------
    def __init__(self, *args, **kwargs):
        """Constructor"""
        canvas.Canvas.__init__(self, *args, **kwargs)
        self.pages = []

    # ----------------------------------------------------------------------
    def showPage(self):
        """
        On a page break, add information to the list
        """
        self.pages.append(dict(self.__dict__))
        self._startPage()

    # ----------------------------------------------------------------------
    def save(self):
        """
        Add the page number to each page (page x of y)
        """
        page_count = len(self.pages)

        for page in self.pages:
            self.__dict__.update(page)
            self.draw_page_number(page_count)
            canvas.Canvas.showPage(self)

        canvas.Canvas.save(self)

    # ----------------------------------------------------------------------
    def draw_page_number(self, page_count):
        """
        Add the page number
        """
        page = "Page %s of %s" % (self._pageNumber, page_count)
        self.setFont("Helvetica", 9)
        self.drawRightString(195 * mm, 272 * mm, page)


def standard_report(file, session, name,  business, db, log, time_log, data=None):
# Function to generate a standard report
    # Extract case information from the session
    case = session.split("@")[1]
    session = session.split("@")[0]
   # Generate hash for verification before the report
    hash_before = Verification.get_hash(os.getcwd() + "\\data\\sessions\\" + session)
  
    # Create a SimpleDocTemplate for the PDF
    doc = SimpleDocTemplate(file, pagesize=letter,
                            rightMargin=72, leftMargin=72,
                            topMargin=72, bottomMargin=18)
      # List to store the content of the PDF report
    Report = []
    logo = "data/img/regsmart.png"

    formatted_time = time.ctime()
    full_name = "Investigator: " + name
    address_parts = business
   # Create an Image instance and add it to the report
    im = Image(logo, 4 * inch, 2 * inch)
    Report.append(im)
    Report.append(Spacer(5, 12))
    # Set up styles for the report
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Justify', alignment=e.TA_JUSTIFY))
    styles.add(ParagraphStyle(name='Center', alignment=e.TA_CENTER))
    styles.add(ParagraphStyle(name='Left', alignment=e.TA_LEFT))
    styles.add(ParagraphStyle(name='Right', alignment=e.TA_RIGHT))
    styles.add(ParagraphStyle(name='Alert', alignment=e.TA_LEFT, backColor="#EFF0F1", borderColor="black",
                              borderWidth=1, borderPadding=5, borderRadius=2, spaceBefore=1, spaceAfter=10))
    styles.add(ParagraphStyle(name='Success', alignment=e.TA_LEFT, backColor="#b0f4b0", borderColor="black",
                              borderWidth=1, borderPadding=5, borderRadius=2, spaceBefore=1, spaceAfter=10))
    styles.add(ParagraphStyle(name='Log', alignment=e.TA_LEFT, backColor="#c6f4f3", borderColor="black",
                              borderWidth=1, borderPadding=5, borderRadius=2, spaceBefore=1, spaceAfter=10))

    ptext = '<font size=18 name="Times-Roman"><b>Reporting</b></font>'
    Report.append(Paragraph(ptext, styles["Center"]))
    Report.append(Spacer(1, 40))

    ptext = '<font size=12>%s</font>' % formatted_time
    Report.append(Paragraph(ptext, styles["Center"]))
    Report.append(Spacer(1, 12))
    Report.append(Spacer(1, 12))

    ptext = '<font size=16>Session: <b>%s</b></font>' % session
    Report.append(Paragraph(ptext, styles["Center"]))
    Report.append(Spacer(1, 30))
    ptext = '<font size=16>Case: <b>%s</b></font>' % case
    Report.append(Paragraph(ptext, styles["Center"]))
    Report.append(Spacer(1, 50))

    # Create return address
    ptext = '<font size=12><b>%s</b></font>' % full_name
    Report.append(Paragraph(ptext, styles["Center"]))
    Report.append(Spacer(1, 20))

    for part in address_parts:
        ptext = '<font size=12>%s</font>' % part.strip()
        Report.append(Paragraph(ptext, styles["Center"]))

    Report.append(PageBreak())
    success = True
    if data:
        if "system" in data:
            try:
                ptext = '<img src="data/img/system.png" valign="-15" /><font size=16 name="Times-Roman">' \
                        '<b>  System Analysis</b></font>'
                Report.append(Paragraph(ptext, styles["Left"]))
                Report.append(Spacer(1, 40))

                system_string = ""
                system = data["system"][1]
                tmp = system["path"].split(";")
                path = list_to_string(tmp)

                system_string += "<b>Computer Name: </b> " + str(system["computer_name"]) + "<br/>"
                system_string += "<b>Product Name: </b>: " + str(system["product_name"]) + "<br/>"
                system_string += "<b>Release ID: </b> " + str(system["release_id"]) + "<br/>"
                system_string += "<b>Process Architecture: </b> " + str(system["process_arch"]) + "<br/>"
                system_string += "<b>Process Count: </b>" + str(system["process_num"]) + "<br/>"
                system_string += "<b>Last Shutdown: </b> " + str(system["shutdown"]) + "<br/>"
                system_string += "<b>Windows Directory: </b> " + str(system["windir"]) + "<br/>"
                system_string += "<b>Path Variables: </b><br/> "

                services_string = list_to_string(data["system"][0], get_database("services.db"), db["services"])

                Report.append(Paragraph(system_string, styles["Left"]))
                Report.append(Spacer(1, 12))
                Report.append(Paragraph("<i>" + path + "</i><br/>", styles["Alert"]))
                Report.append(Spacer(1, 12))
                if db["services"].get():
                    Report.append(Paragraph("<b>Services(services.db): </b><br/>", styles["Left"]))
                else:
                    Report.append(Paragraph("<b>Services: </b><br/>", styles["Left"]))
                Report.append(Spacer(1, 12))
                Report.append(Paragraph("<i>" + services_string + "</i>", styles["Alert"]))
                Report.append(PageBreak())
            except Exception as ee:
                print(ee)
                success = False

        if "os" in data:
            try:
                ptext = '<img src="data/img/os.png" valign="-15" /><font size=16 name="Times-Roman">' \
                        '<b>  OS Analysis</b></font>'
                Report.append(Paragraph(ptext, styles["Left"]))
                Report.append(Spacer(1, 40))

                os_string = ""
                osdata = data["os"][0]

                os_string += "<b>Product Name: </b> " + str(osdata["ProductName"]) + "<br/>"
                os_string += "<b>Release ID: </b> " + str(osdata["ReleaseId"]) + "<br/>"
                os_string += "<b>Product ID: </b> " + str(osdata["ProductId"]) + "<br/>"
                os_string += "<b>Current OS Build: </b> " + str(osdata["CurrentBuild"]) + "<br/>"
                os_string += "<b>Path Name: </b> " + str(osdata["PathName"]) + "<br/>"
                os_string += "<b>Installed Date: </b> " + str(osdata["InstallDate"]) + "<br/>"
                os_string += "<b>Registered Organization: </b> " + str(osdata["RegisteredOrganization"]) + "<br/>"
                os_string += "<b>Registered Owner: </b> " + str(osdata["RegisteredOwner"]) + "<br/>"

                Report.append(Paragraph(os_string, styles["Left"]))
                Report.append(Spacer(1, 20))

                sid_list = data["os"][1]
                users_paths_list = data["os"][2]
                mapping_list = data["os"][3]
                accounts = data["os"][4]
                up = []
                up.insert(0, ["#Sid", "#Username", "#Path"])

                for i in range(0, len(sid_list)):
                    up.append([ Paragraph(sid_list[i], styles['Normal']),
                                Paragraph(mapping_list[i], styles['Normal']),
                                Paragraph(users_paths_list[i], styles['Normal'])])

                t = Table(up)
                t.setStyle(TableStyle([
                           ('INNERGRID', (0,0), (-1,-1), 0.25, colors.black),
                           ('HEADER', (0, 0), (0, 2), 0.25, colors.green),
                           ('BOX', (0,0), (-1,-1), 0.25, colors.black),
                           ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold')
                           ]))
                Report.append(Paragraph("<b>User Profiles: </b>", styles["Left"]))
                Report.append(Spacer(1, 12))
                Report.append(t)
                Report.append(Spacer(1, 20))

                Report.append(Paragraph("<b>Accounts: </b>", styles["Left"]))
                Report.append(Spacer(1, 12))
                Report.append(Paragraph("<i>" + list_to_string(accounts) + "</i>", styles["Alert"]))
                Report.append(PageBreak())
            except Exception as ee:
                print(ee)
                success = False
        if "network" in data:
            try:
                ptext = '<img src="data/img/network.png" valign="-15" /><font size=16 name="Times-Roman">' \
                        '<b>  Network Analysis</b></font>'
                Report.append(Paragraph(ptext, styles["Left"]))
                Report.append(Spacer(1, 40))

                cards, intranet, wireless, matched = data["network"]

                Report.append(Paragraph("<b>Network Cards: </b>", styles["Left"]))
                Report.append(Spacer(1, 12))
                Report.append(Paragraph("<i>" + list_to_string(cards) + "</i>", styles["Alert"]))
                Report.append(Spacer(1, 20))

                Report.append(Paragraph("<b>Intranet Connections: </b>", styles["Left"]))
                Report.append(Spacer(1, 12))
                Report.append(Paragraph("<i>" + list_to_string(intranet) + "</i>", styles["Alert"]))
                Report.append(Spacer(1, 20))

                up = []
                up.insert(0, ["Description", "Date Created", "Date Last Connected", "ID"])

                for m in matched:
                    up.append([Paragraph(m["Description"], styles['Normal']),
                               Paragraph(m["Created"], styles['Normal']),
                               Paragraph(m["Modified"], styles['Normal']),
                               Paragraph(m["ID"], styles['Normal'])])

                t = Table(up, colWidths=[6 * cm, 4 * cm, 4 * cm, 5 * cm])
                t.setStyle(TableStyle([
                           ('BACKGROUND',(0,0),(-1,0),colors.lightgrey),
                           ('GRID',(0,1),(-1,-1),0.01*inch,(0,0,0,)),
                           ('FONT', (0,0), (-1,0), 'Helvetica-Bold')]))

                Report.append(Paragraph("<b>Wireless Networks: </b>", styles["Left"]))
                Report.append(Spacer(1, 12))
                Report.append(t)
                Report.append(PageBreak())

            except Exception as ee:
                print(ee)
                success = False

        if "device" in data:
            try:
                ptext = '<img src="data/img/device1.png" valign="-15" /><font size=16 name="Times-Roman">' \
                        '<b>  Device Analysis</b></font>'
                Report.append(Paragraph(ptext, styles["Left"]))
                Report.append(Spacer(1, 40))
                printer, usb = data["device"]

                Report.append(Paragraph("<b>Printer Drivers: </b>", styles["Left"]))
                Report.append(Spacer(1, 12))
                Report.append(Paragraph("<i>" + list_to_string(printer) + "</i>", styles["Alert"]))
                Report.append(Spacer(1, 20))

                up = []
                up.insert(0, ["Serial", "Vendor", "Product", "Installed Date", "Plugged Date", "Unplugged Date"])

                for u in usb:
                    vendor = u["Vendor"]
                    product = u["Product"]
                    for z in u["Serial"]:
                        up.append([Paragraph(z['ID'], styles["Normal"]),
                                  Paragraph(vendor, styles["Normal"]),
                                  Paragraph(product, styles["Normal"]),
                                  Paragraph(str(z['InstallDate']), styles["Normal"]),
                                  Paragraph(str(z['LastArrivalDate']), styles["Normal"]),
                                  Paragraph(str(z['LastRemovalDate']), styles["Normal"])])

             # Create a table 't' with specified column widths and styling for USB-related information
t = Table(up, colWidths=[5 * cm, 3 * cm, 3 * cm, 2.5 * cm, 2.5 * cm, 3 * cm])
t.setStyle(TableStyle([
    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),  # Set background color for the header row
    ('GRID', (0, 1), (-1, -1), 0.01 * inch, (0, 0, 0,)),  # Add grid lines to the table
    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold')  # Set bold font for the header row
]))

# Add a header indicating USB-related information to the report using the specified style ("Left")
Report.append(Paragraph("<b>USB: </b>", styles["Left"]))

# Add a vertical space of 12 units after the USB header for formatting
Report.append(Spacer(1, 12))

# Add the USB table 't' to the report
Report.append(t)

# Catch any exceptions that might occur during this section and set 'success' to False if an exception is caught
except Exception as ee:
    print(ee)
    success = False


# Check if previous sections of the report generation were successful
if success:
    # Add a vertical space of 40 units in the report for visual separation
    Report.append(Spacer(1, 40))
    
    # Calculate the hash of the session directory after generating the report
    hash_after = Verification.get_hash(os.getcwd() + "\\data\\sessions\\" + session)
    
    # Add a header indicating hash verifications with specified style ("Left")
    Report.append(Paragraph("<b>Hash Verifications: </b><br/>", styles["Left"]))
    
    # Add a vertical space of 12 units after the hash verification header for formatting
    Report.append(Spacer(1, 12))

        hashes = "<b>Session Before Report:</b> " + hash_before + "<br/>"
        hashes += "<b>Session After Report:&nbsp; </b> " + hash_after + "<br/>"
        hashes += "<b>Exclusion Databases: </b> <br/>"

        for filename in os.listdir(os.getcwd() + "\\data\\db"):
            hashes += "<b>  *" + filename + ": </b> " + \
                      Verification.get_hash(os.getcwd() + "\\data\\db\\" + filename) + "<br/>"

        Report.append(Paragraph(hashes, styles["Success"]))
        Report.append(Spacer(1, 12))

        if hash_before == hash_after:
            im = Image("data/img/regsmartcertified.png", 3 * inch, 1 * inch)
            Report.append(im)
            Report.append(Spacer(5, 12))

    Report.append(PageBreak())
    Report.append(Paragraph("<b>User Activity Timeline: </b><br/>", styles["Left"]))

    labels, y, x1, x2 = parse_log(time_log)

    import matplotlib.pyplot as plt
    fig = plt.figure(figsize=(12, 6))
    hax = fig.add_subplot(111)
    hax.hlines(y, x1, x2)

    hax.set_xlabel('Time (min)')
    hax.set_ylabel('Activity')
    plt.savefig('data/img/Timeline.png')
    im = Image("data/img/Timeline.png", 8 * inch, 4 * inch)
    Report.append(im)
    Report.append(Spacer(5, 12))
    # data = [x1]
    # lc = HorizontalLineChart()
    # lc.x = 50
    # lc.y = 50
    # lc.height = 300
    # lc.width = 450
    # lc.data = data
    # lc.joinedLines = 1
    # catNames = labels
    # lc.categoryAxis.categoryNames = catNames
    # lc.categoryAxis.labels.boxAnchor = 'ne'
    # lc.valueAxis.valueMin = 0
    # lc.valueAxis.valueMax = 60
    # lc.valueAxis.valueStep = 5
    # lc.lines[0].strokeWidth = 2
    # lc.lines[1].strokeWidth = 1.5
    # drawing.add(lc)
    # Report.append(drawing)
    Report.append(Paragraph("<b>User Log: </b><br/>", styles["Left"]))
    Report.append(Spacer(1, 12))
    Report.append(Paragraph(log, styles["Log"]))

    # Build Report
    Report.append(Spacer(1, 12))
    doc.build(Report, canvasmaker=PageNumCanvas)





def parse_log(time_log):
    data_x1 = []
    data_x2 = []
    data_y = []
    labels = []

    t1 = time_log[0]
    tn = time_log[-1]
    t1d = datetime.timedelta(hours=t1.hour, minutes=t1.minute, seconds=t1.second)

    num = 0
    data = []
    for t in time_log:
        d = datetime.timedelta(hours=t.hour, minutes=t.minute, seconds=t.second) - t1d
        data.append(d.seconds / 60)
    tmp = data[0]
    for d in data:
        data_x1.append(d)
        data_x2.append(tmp)
        tmp = d

    for i in range(0, len(data_x1)):
        data_y.append(i)
        labels.append(i)

    # data_x1 = data_x1[:-1]
    # data_x2 = data_x2[1:]
    print(data_x1)
    print(data_x2)
    return labels, data_y, data_x1,  data_x2


def get_database(filename):
    # Initialize an empty list to store data from the database file
    data = []

    try:
        # Open the specified database file in read text mode
        with open("data/db/" + filename, "rt") as f:
            # Iterate through each line in the file
            for line in f:
                # Split the line into a list based on commas
                tmp = line.split(',')
                
                # Iterate through the elements in the temporary list
                for t in tmp:
                    # Add the stripped and cleaned element to the data list
                    data.append(t.strip(' ').strip('\n'))
    
    except Exception:
        # Catch any exceptions that might occur during file processing
        pass

    # Return the collected data from the database file
    return data



def list_to_string(list_data, db=None, use=None):
    # Convert a list to a formatted string for inclusion in the report
    list_str = ""

    # Iterate over the elements of the list along with their indices
    for i, l in enumerate(list_data):
        # Check if 'use' parameter is provided and has a truth value
        if use:
            # Check if the 'get' method of 'use' is true (e.g., a boolean variable or function)
            if use.get():
                # Check if 'db' parameter is provided and the current element is not in the exclusion database
                if db and str(l) not in db:
                    list_str += str(i) + ": " + str(l) + "<br/>"
                else:
                    list_str += str(i) + ": " + str(l) + "<br/>"
            else:
                list_str += str(i) + ": " + str(l) + "<br/>"
        else:
            # If 'use' is not provided, simply add the element with its index to the string
            list_str += str(i) + ": " + str(l) + "<br/>"
    
    return list_str


def coord(x, y, unit=1):
    # Convert coordinates from user-defined units to standard units (e.g., A4 paper size)
    width, height = A4
    x, y = x * unit, height - y * unit
    return x, y

        
