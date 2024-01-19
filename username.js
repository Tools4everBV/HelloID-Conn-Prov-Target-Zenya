function getUsername() {
    let userPrincipalName = Person.Accounts.MicrosoftActiveDirectory.userPrincipalName;
    return userPrincipalName;
}
getUsername();