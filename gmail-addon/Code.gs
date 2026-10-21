
var BASE_URL = "https://YOUR_NGROK_DOMAIN/api";

var SCAN_URL = BASE_URL + "/scan";
var REPORT_URL = BASE_URL + "/report";
var VERIFY_URL = BASE_URL + "/verify";
var VERIFY_STATUS_URL = BASE_URL + "/verification-status";

// Sends authenticated requests to the backend.
function apiRequest(url, method, payload) {
  var identityToken = ScriptApp.getIdentityToken();

  if (!identityToken) {
    throw new Error("No Google ID token. Check the openid scope and reauthorize.");
  }

  var options = {
    method: method,
    headers: {
      Authorization: "Bearer " + identityToken,
      "ngrok-skip-browser-warning": "true"
    },
    muteHttpExceptions: true
  };

  if (payload !== undefined) {
    options.contentType = "application/json";
    options.payload = JSON.stringify(payload);
  }

  var response = UrlFetchApp.fetch(url, options);
  var httpStatus = response.getResponseCode();

  if (httpStatus < 200 || httpStatus >= 300) {
    throw new Error("Backend returned HTTP " + httpStatus);
  }

  return JSON.parse(response.getContentText());
}

function postJson(url, payload) {
  return apiRequest(url, "post", payload);
}

function getJson(url) {
  return apiRequest(url, "get");
}

// Retrieves the verification status directly from the backend.
function getVerificationStatus() {
  return getJson(VERIFY_STATUS_URL);
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function getActionParameters(e) {
  return (e.commonEventObject && e.commonEventObject.parameters) ||
         e.parameters || {};
}

function getOpenedMessage(e) {
  var gmail = e.gmail || {};
  var metadata = e.messageMetadata || {};
  var parameters = getActionParameters(e);

  var messageId =
    metadata.messageId || gmail.messageId || parameters.messageId;

  var accessToken = metadata.accessToken || gmail.accessToken;

  if (!messageId || !accessToken) {
    throw new Error("Missing Gmail message context; reopen the email.");
  }

  GmailApp.setCurrentMessageAccessToken(accessToken);
  return GmailApp.getMessageById(messageId);
}

function showError(err) {
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification()
        .setText("Error: " + err.message)
    )
    .build();
}

function buildErrorCard(err) {
  return [
    CardService.newCardBuilder()
      .setHeader(
        CardService.newCardHeader().setTitle("Error")
      )
      .addSection(
        CardService.newCardSection()
          .addWidget(
            CardService.newTextParagraph()
              .setText(escapeHtml(err.message))
          )
      )
      .build()
  ];
}

// Main entry point: the backend determines the user's verification state.
function buildAddOn(e) {
  try {
    var status = getVerificationStatus();

    return status.fullyVerified
      ? buildScanCard(e)
      : buildVerificationCard(e, status);

  } catch (err) {
    return buildErrorCard(err);
  }
}

// ==========================================
// Verification Flow
// ==========================================

function buildVerificationCard(e, status) {
  var section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText(
          "כדי להגן על המערכת מפני דיווחי שווא , עלינו לוודא שיש לך תיבת מייל פעילה."
        )
    )
    .addWidget(
      CardService.newTextParagraph().setText(
        "<b>הוראות:</b><br>" +
        "1. פתח " + escapeHtml(status.requiredEmails) +
        " אימיילים שונים מהעבר (ישנים מ-" +
        escapeHtml(status.minAgeDays) + " יום).<br>" +
        "2. ודא שהם נשלחו מאנשים שונים ובהפרש של " +
        escapeHtml(status.minIntervalDays) + " ימים אחד מהשני.<br>" +
        "3. לחץ על הכפתור מטה בכל אחד מהם."
      )
    )
    .addWidget(
      CardService.newTextParagraph()
        .setText(
          "<b>התקדמות אימות: " +
          escapeHtml(status.progress) + "/" +
          escapeHtml(status.requiredEmails) + "</b>"
        )
    );

  var verifyButton = CardService.newTextButton()
    .setText("✅ Verify This Email")
    .setOnClickAction(
      CardService.newAction()
        .setFunctionName("verifyCurrentEmail")
    );

  section.addWidget(
    CardService.newButtonSet().addButton(verifyButton)
  );

  return [
    CardService.newCardBuilder()
      .setHeader(
        CardService.newCardHeader()
          .setTitle("Account Verification")
      )
      .addSection(section)
      .build()
  ];
}

function verifyCurrentEmail(e) {
  try {
    var message = getOpenedMessage(e);

    var result = postJson(VERIFY_URL, {
      emailSender: message.getFrom(),
      emailDateMs: message.getDate().getTime()
    });

    var nav;

    if (result.fullyVerified) {
      nav = CardService.newNavigation()
        .updateCard(buildScanCard(e)[0]);
    } else {
      nav = CardService.newNavigation()
        .updateCard(buildVerificationCard(e, result)[0]);
    }

    return CardService.newActionResponseBuilder()
      .setNavigation(nav)
      .setNotification(
        CardService.newNotification()
          .setText(result.message || "Verification processed.")
      )
      .build();

  } catch (err) {
    return showError(err);
  }
}

// ==========================================
// Main Scanner Flow
// ==========================================

function buildScanCard(e) {
  var message = getOpenedMessage(e);
  var sender = message.getFrom();
  var subject = message.getSubject();

  var section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph()
        .setText("<b>Sender:</b> " + escapeHtml(sender))
    )
    .addWidget(
      CardService.newTextParagraph()
        .setText("<b>Subject:</b> " + escapeHtml(subject))
    )
    .addWidget(
      CardService.newTextButton()
        .setText("🔍 Scan Email")
        .setOnClickAction(
          CardService.newAction()
            .setFunctionName("triggerScan")
            .setParameters({messageId: message.getId()})
        )
    );

  return [
    CardService.newCardBuilder()
      .setHeader(
        CardService.newCardHeader()
          .setTitle("Email Scorer - Upwind")
      )
      .addSection(section)
      .build()
  ];
}

function triggerScan(e) {
  try {
    var message = getOpenedMessage(e);
    var attachments = message.getAttachments();
    var attachmentNames = [];

    for (var i = 0; i < attachments.length; i++) {
      attachmentNames.push(attachments[i].getName());
    }

    var sender = message.getFrom();

    var result = postJson(SCAN_URL, {
      sender: sender,
      subject: message.getSubject(),
      body: message.getPlainBody(),
      attachmentNames: attachmentNames
    });

    var section = CardService.newCardSection()
      .addWidget(
        CardService.newTextParagraph()
          .setText("<b>Verdict:</b> " + escapeHtml(result.verdict))
      )
      .addWidget(
        CardService.newTextParagraph()
          .setText(
            "<b>Maliciousness Score:</b> " +
            escapeHtml(result.score) + "/100"
          )
      );

    if (Array.isArray(result.reasons) && result.reasons.length > 0) {
      section.addWidget(
        CardService.newTextParagraph().setText(
          "<b>Reasons:</b><br>• " +
          result.reasons.map(escapeHtml).join("<br>• ")
        )
      );
    }

    section.addWidget(
      CardService.newButtonSet()
        .addButton(
          CardService.newTextButton()
            .setText("🚨 Report as Phishing")
            .setOnClickAction(
              CardService.newAction()
                .setFunctionName("reportPhishing")
                .setParameters({sender: sender})
            )
        )
    );

    var resultCard = CardService.newCardBuilder()
      .setHeader(
        CardService.newCardHeader()
          .setTitle("Scan Results")
      )
      .addSection(section)
      .build();

    return CardService.newActionResponseBuilder()
      .setNavigation(
        CardService.newNavigation().pushCard(resultCard)
      )
      .build();

  } catch (err) {
    return showError(err);
  }
}

// ==========================================
// Community Reporting Flow
// ==========================================

function reportPhishing(e) {
  try {
    var sender = getActionParameters(e).sender;

    if (!sender) {
      throw new Error("Missing sender");
    }

    var result = postJson(REPORT_URL, {
      sender: sender
    });

    var popupMessage;

    if (result.status === "new") {
      popupMessage = "Reported to community successfully!";
    } else if (result.status === "exists") {
      popupMessage = "You have already reported this sender!";
    } else if (result.status === "unverified") {
      popupMessage = "Verification required. Reopen the add-on.";
    } else {
      popupMessage = "Report could not be confirmed.";
    }

    return CardService.newActionResponseBuilder()
      .setNotification(
        CardService.newNotification()
          .setText(popupMessage)
      )
      .build();

  } catch (err) {
    return showError(err);
  }
}
