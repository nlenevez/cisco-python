
import pandas as pd
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# Paths
csv_file = '/tmp/tunnel_mtu_report.csv'  # CSV from Ansible playbook
pdf_file = '/tmp/tunnel_mtu_full_report.pdf'

# Read CSV
df = pd.read_csv(csv_file)

# Summary stats
total_tunnels = len(df)
mismatched_mtu = len(df[df['MTU Match'] == 'No'])
failed_pings = len(df[df['Ping Result'] != 'Pass'])

summary = [
    ['Total Tunnels', total_tunnels],
    ['MTU Mismatches', mismatched_mtu],
    ['Ping Failures', failed_pings],
    ['MTU Match %', f"{round(((total_tunnels - mismatched_mtu) / total_tunnels) * 100, 2)}%"],
    ['Ping Success %', f"{round(((total_tunnels - failed_pings) / total_tunnels) * 100, 2)}%"]
]

# Generate charts
plt.figure(figsize=(6,4))
df['MTU Match'].value_counts().plot(kind='bar', color=['green','red'])
plt.title('MTU Match vs Mismatch')
plt.ylabel('Count')
plt.tight_layout()
plt.savefig('/tmp/mtu_chart.png')
plt.close()

plt.figure(figsize=(6,4))
df['Ping Result'].value_counts().plot(kind='bar', color=['blue','orange'])
plt.title('Ping Pass vs Fail')
plt.ylabel('Count')
plt.tight_layout()
plt.savefig('/tmp/ping_chart.png')
plt.close()

# Prepare PDF
styles = getSampleStyleSheet()
doc = SimpleDocTemplate(pdf_file, pagesize=A4)
elements = []

# Title
elements.append(Paragraph("Tunnel MTU Validation Report", styles['Title']))
elements.append(Spacer(1, 12))

# Summary Table
elements.append(Paragraph("Summary Statistics", styles['Heading2']))
summary_table = Table(summary, colWidths=[200, 200])
summary_table.setStyle(TableStyle([
    ('BACKGROUND', (0,0), (-1,0), colors.grey),
    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
    ('BOTTOMPADDING', (0,0), (-1,0), 12),
    ('BACKGROUND', (0,1), (-1,-1), colors.beige),
    ('GRID', (0,0), (-1,-1), 1, colors.black)
]))
mtu_chart.png', width=400, height=300))
elements.append(Image('/tmp/ping_chart.png', width=400, height=300))
elements.append(Spacer(1, 24))

# Detailed Table
elements.append(Paragraph("Detailed Tunnel Data", styles['Heading2']))
data_table = [df.columns.tolist()] + df.values.tolist()
detail_table = Table(data_table, colWidths=[70]*len(df.columns))
detail_table.setStyle(TableStyle([
    ('BACKGROUND', (0,0), (-1,0), colors.grey),
    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
    ('GRID', (0,0), (-1,-1), 0.5, colors.black)
]))
elements.append(detail_table)

# Build PDF
doc.build(elements)
print(f"PDF report generated successfully: {pdf_file}")
