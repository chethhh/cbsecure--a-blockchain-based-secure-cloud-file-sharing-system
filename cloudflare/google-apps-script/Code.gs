/**
 * Small HTTPS bridge for Cloudflare Workers to send CB SECURE OTPs via Gmail.
 * Deploy as a Web app that executes as the owning Google account.
 * Set OTP_RELAY_TOKEN in Apps Script Project Settings > Script properties.
 */
function doPost(event) {
  try {
    const payload = JSON.parse(event?.postData?.contents || "{}");
    const expectedToken = PropertiesService.getScriptProperties().getProperty("OTP_RELAY_TOKEN") || "";
    if (expectedToken.length < 32 || !constantTimeEquals(String(payload.token || ""), expectedToken)) {
      return jsonResponse({ ok: false, error: "Unauthorized" }, 401);
    }

    const to = String(payload.to || "").trim();
    const code = String(payload.code || "");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to) || !/^\d{6}$/.test(code)) {
      return jsonResponse({ ok: false, error: "Invalid recipient or verification code" }, 400);
    }

    GmailApp.sendEmail(
      to,
      "Your CB SECURE verification code",
      "Your one-time verification code is " + code + ". It expires in five minutes.",
      { name: "CB SECURE" },
    );
    return jsonResponse({ ok: true });
  } catch (error) {
    console.error("OTP relay failed", error?.message || "Unknown error");
    return jsonResponse({ ok: false, error: "Could not send verification email" }, 500);
  }
}

function constantTimeEquals(actual, expected) {
  let difference = actual.length ^ expected.length;
  const length = Math.max(actual.length, expected.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (actual.charCodeAt(index) || 0) ^ (expected.charCodeAt(index) || 0);
  }
  return difference === 0;
}

function jsonResponse(value) {
  return ContentService
    .createTextOutput(JSON.stringify(value))
    .setMimeType(ContentService.MimeType.JSON);
}
