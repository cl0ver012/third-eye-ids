from tensorflow import Tensor
from tensorflow.keras import Model
from numpy import ndarray, argmax, vectorize, max

def predict(X: ndarray or Tensor, model: Model, return_raw_tensors: bool = False, labels: dict = None):
  """
  To predict the class name (Benign or Intrusion), class IDs, and confidence scores for the prediction of the input tensor/array.
  
  Args:
    * X: Input array/tensor containing the network traffic data with selected features.
    * return_raw_tensors: True or False value denoting if the prediction tensor should be returned as it is or the predictions should be returned as class names, class IDs, and confidence scores.
  
  Returns:
    * pred: Predicted values as a tensor/array.
    * class_ids: Array of predicted class IDs for the input tensor (batch wise).
    * confidence_scores: Array of confidence scores/maximum probability values for the predicted class for the given input tensor (batch wise).
    * class_names: List of predicted class names for the input tensor (batch wise).
  """
  # Reshape input tensor to batch, features
  X = X.reshape((-1, 31))
  
  # predict using the pre-trained model and reshape it into batch, classes
  pred = model.predict(X)
  # take argmax on the first axis to get class index of the predictions for the batch
  class_ids = argmax(pred, axis=1)
  # get class names from the predicted class ids for the batch by mapping it using the LABELS dictionary
  class_names = vectorize(labels.get)(class_ids).tolist()
  # get confidence scores for the batch by taking maximum on the first axis for each prediction
  confidence_scores = max(pred, axis=1)
  
  # if return_raw_tensors is selected, return the predcited tensor as it is
  if return_raw_tensors:
    return pred

  # return the class names, class IDs, and confidence scores for each prediction in the batch
  return class_names, class_ids, confidence_scores