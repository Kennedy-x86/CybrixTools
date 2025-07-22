from PIL import Image
import numpy as np

#Upload image and get RGB
def get_image(image_path):
    img = Image.open(image_path).convert('RGB')
    return np.array(img)

#Standard deviation of least significant bits
def lsb_stat(data):
    lsb = data & 1
    var = np.std(lsb)
    return var

#Detect abnormal pixels
def ab_pix(data):
    anomaly = []
    for channel in range(data.shape[2]):
        ch_std = np.std(data[:, :, channel])
        if ch_std < 10 or ch_std > 60:
            anomaly.append(channel)
    return anomaly

def check_upload(image_path):
    """
    Check for anything abnormal based on stats
    """

    data = get_image(image_path)
    lsb_s = lsb_stat(data)
    anomaly = ab_pix(data)

    likelihood = 1.0 - lsb_s
    if anomaly:
        likelihood += 0.2
    likelihood = min(1.0, likelihood)

    findings = []
    findings.append(f"LSB variation is: {lsb_s:.4f}")
    if anomaly:
        findings.append(f"Anomaly is: {', '.join(str(a) for a in anomaly)}")
    else:
        findings.append("No major anomalies found")
    findings.append(f"Chances of steganography are: {likelihood * 100:.2f}%")

    return likelihood, findings
