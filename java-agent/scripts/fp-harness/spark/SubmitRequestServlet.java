package org.apache.spark.deploy.rest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class SubmitRestProtocolMessage {}
class CreateSubmissionRequest extends SubmitRestProtocolMessage {}
class SubmitRestProtocolResponse {}

/** The Spark servlet ABI, with a receipt as the only handler side effect. */
public final class SubmitRequestServlet {
  public String descriptor;
  public boolean creation = true;
  public boolean valid = true;
  public int receipts;

  public void doPost(HttpServletRequest request, HttpServletResponse response) {
    if (!valid) return;
    SubmitRestProtocolMessage message = creation ? new CreateSubmissionRequest() : new SubmitRestProtocolMessage();
    handleSubmit(descriptor, message, response);
  }

  protected SubmitRestProtocolResponse handleSubmit(String text, SubmitRestProtocolMessage message,
      HttpServletResponse response) {
    receipts++;
    return new SubmitRestProtocolResponse();
  }
}
