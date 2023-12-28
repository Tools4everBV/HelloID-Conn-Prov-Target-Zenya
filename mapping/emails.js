function getEmails() {
    let mail = Person.Accounts.MicrosoftActiveDirectory.mail;

    return [
        "work:" + mail
    ];
}
getEmails();