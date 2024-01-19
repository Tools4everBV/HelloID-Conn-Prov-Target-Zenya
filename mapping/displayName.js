// logic to generate the displayName based on name convention.
// B    Alexandra van der Wal
// P    Alexandra de Vries
// BP   Alexandra van der Wal - de Vries
// PB   Alexandra de Vries - van der Wal
function generateDisplayName() {
    let firstName = Person.Name.NickName;
    let middleName = Person.Name.FamilyNamePrefix;
    let lastName = Person.Name.FamilyName;
    let middleNamePartner = Person.Name.FamilyNamePartnerPrefix;
    let lastNamePartner = Person.Name.FamilyNamePartner;
    let convention = Person.Name.Convention;
    let nameFormatted = '';

    switch (convention) {
        case 'B':
            // Alexandra van der Wal
            nameFormatted = firstName; // Alexandra
            if (typeof middleName !== 'undefined' && middleName) { nameFormatted = nameFormatted + ' ' + middleName } // Alexandra van der
            nameFormatted = nameFormatted + ' ' + lastName // Alexandra van der Wal
            break;
        case 'BP':
            // Alexandra van der Wal - de Vries
            nameFormatted = firstName; // Alexandra
            if (typeof middleName !== 'undefined' && middleName) { nameFormatted = nameFormatted + ' ' + middleName } // Alexandra van der
            nameFormatted = nameFormatted + ' ' + lastName // Alexandra van der Wal

            nameFormatted = nameFormatted + ' -' // Alexandra van der Wal -

            if (typeof middleNamePartner !== 'undefined' && middleNamePartner) { nameFormatted = nameFormatted + ' ' + middleNamePartner } // Alexandra van der Wal - de  
            nameFormatted = nameFormatted + ' ' + lastNamePartner; // Alexandra van der Wal - de Vries
            break;
        case 'P':
            // Alexandra de Vries
            nameFormatted = firstName; // Alexandra
            if (typeof middleNamePartner !== 'undefined' && middleNamePartner) { nameFormatted = nameFormatted + ' ' + middleNamePartner } // Alexandra de
            nameFormatted = nameFormatted + ' ' + lastNamePartner; // Alexandra de Vries
            break;
        case 'PB':
            // Alexandra de Vries - van der Wal
            nameFormatted = firstName; // Alexandra
            if (typeof middleNamePartner !== 'undefined' && middleNamePartner) { nameFormatted = nameFormatted + ' ' + middleNamePartner } // Alexandra de
            nameFormatted = nameFormatted + ' ' + lastNamePartner; // Alexandra de Vries

            nameFormatted = nameFormatted + ' -' // Alexandra de Vries -

            if (typeof middleName !== 'undefined' && middleName) { nameFormatted = nameFormatted + ' ' + middleName } // Alexandra de Vries - van der
            nameFormatted = nameFormatted + ' ' + lastName // Alexandra de Vries - van der Wal
            break;
        default:
            // Alexandra van der Wal
            nameFormatted = firstName; // Alexandra
            if (typeof middleName !== 'undefined' && middleName) { nameFormatted = nameFormatted + ' ' + middleName } // Alexandra van der
            nameFormatted = nameFormatted + ' ' + lastName // Alexandra van der Wal
            break;
    }

    return nameFormatted;
}

generateDisplayName();