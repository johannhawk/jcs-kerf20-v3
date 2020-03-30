#Búa til ou Notendur
New-ADOrganizationalUnit -Name Notendur -ProtectedFromAccidentalDeletion $false
#Búa til security group (SG) Allir ---        eep-johann.local
New-ADGroup -Name Allir -Path "ou=notendur,dc=eep-johann,dc=local" -GroupScope Global 
#Lesa inn skrá í breytu
$notendur = Import-Csv C:\scrip\v3_notendur_u.csv

#Fyrir hvern notanda í breytunni
foreach($n in $notendur) {
    #Athuga hvort deildar OU er til 
    $deild = $n.deild
    if(-not(Get-ADOrganizationalUnit -Filter {name -like $deild})) {
        #Búa OU til ef það er ekki til
        New-ADOrganizationalUnit -Name $n.deild -Path "ou=Notendur,dc=eep-johann,dc=local"
        #Búa til SG fyrir deild
        New-ADGroup -Name $n.deild -Path $("ou=" + $n.deild + ",ou=notendur,dc=eep-johann,dc=local") -GroupScope Global 
        #Setja deildar SG í Allir SG
        Add-ADGroupMember -Identity Allir -Members $n.deild
    }
    #Búa til notanda
    New-ADUser -Name $n.nafn -DisplayName $n.nafn -GivenName $n.fornafn -Surname $n.eftirnafn -SamAccountName $n.notendanafn -UserPrincipalName $($n.notendanafn + "@eep-johann.local") -HomePhone $n.heimasimi -OfficePhone $n.vinnusimi -MobilePhone $n.farsimi -Path $("ou=" + $n.deild + ",ou=notendur,dc=eep-johann,dc=local") -AccountPassword (ConvertTo-SecureString -AsPlainText "pass.123" -Force) -Enabled $true
    #Setja notanda í deildar SG
    Add-ADGroupMember -Identity $n.deild -Members $n.notendanafn

}