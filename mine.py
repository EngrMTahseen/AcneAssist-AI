# import torch
# from PIL import Image
# import os
# import numpy as np
# model_path = os.path.join('static', 'models', 'last.pt')
# model = torch.hub.load('computervisioneng/yolov9', 'custom', path=model_path)
# def detect_acne(image_path):
#     img = Image.open(image_path).convert('RGB')
#     img = np.array(img)
#     results = model(img)
#     results.show()
#     return results
# image_path = 'static/uploads/12.jpg'
# detect_acne(image_path)




# import torch
# from PIL import Image
# import os
# from pathlib import Path
# import numpy as np
#
# model_path = os.path.join('static', 'models', 'last.pt')
# model = torch.hub.load('computervisioneng/yolov9', 'custom', path=model_path)
#
#
# def detect_acne(image_path):
#     img = Image.open(image_path).convert('RGB')
#     img = np.array(img)
#     results = model(img)
#
#     # Set the directory where results will be saved
#     results_dir = os.path.join('static', 'results')
#
#     # Ensure the directory exists
#     if not os.path.exists(results_dir):
#         os.makedirs(results_dir)
#
#     # Modify results object to save images to the specified directory
#     results._run(save=True, save_dir=Path(results_dir))
#
#     return results
#
#
# image_path = 'static/uploads/12.jpg'
# detect_acne(image_path)


import torch
from PIL import Image
import os
from pathlib import Path
import numpy as np

model_path = os.path.join('static', 'models', 'last.pt')
model = torch.hub.load('computervisioneng/yolov9', 'custom', path=model_path)

def detect_acne(image_path):
    img = Image.open(image_path).convert('RGB')
    img = np.array(img)
    results = model(img)

    # Set the directory where results will be saved
    results_dir = os.path.join('static', 'results')

    # Ensure the directory exists
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    # Modify results object to save images to the specified directory
    results._run(save=True, save_dir=Path(results_dir))

    # Convert results to DataFrame and get class names and counts
    results_df = results.pandas().xyxy[0]  # Pandas DataFrame of detections
    class_names = results_df['name'].unique()  # Unique class names
    class_counts = results_df['name'].value_counts()  # Counts of each class

    # Print class names and counts
    print("Class Names and Counts:")
    for class_name, count in class_counts.items():
        print(f"{class_name}: {count}")

    return results

image_path = 'static/uploads/12.jpg'
detect_acne(image_path)
