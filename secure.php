<?php
if($_SERVER["REQUEST_METHOD"] == "POST") {

    // Basic sanitization
    $name = strip_tags(trim($_POST['name']));
    $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
    $subject = strip_tags(trim($_POST['subject']));
    $message = strip_tags(trim($_POST['message']));

    // Honeypot anti-bot
    if(!empty($_POST['website'])) {
        http_response_code(400);
        echo "Bot submission detected.";
        exit;
    }

    // Validate input
    if(empty($name) || empty($email) || empty($subject) || empty($message)) {
        http_response_code(400);
        echo "Please fill in all fields.";
        exit;
    }

    if(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo "Invalid email address.";
        exit;
    }

    // Prevent Email Header Injection
    $pattern = '/[\r\n]|Content-Type:|Bcc:|Cc:/i';
    if(preg_match($pattern, $name) || preg_match($pattern, $email) || preg_match($pattern, $subject)) {
        http_response_code(400);
        echo "Invalid input detected.";
        exit;
    }

    // Prepare email
    $to = "info@simplyrevived.co.za";
    $headers = "From: $name <$email>\r\n";
    $headers .= "Reply-To: $email\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";

    // Send email
    if(mail($to, $subject, $message, $headers)) {
        echo "Thank you! Your message has been sent.";
    } else {
        http_response_code(500);
        echo "Sorry, something went wrong. Please try again later.";
    }

} else {
    http_response_code(403);
    echo "There was a problem with your submission.";
}
?>
