import XRegExp from 'xregexp';

// The regexes are imported from https://github.com/joepie91/python-whois
const grammarRegexes = {
  'id': [
    /Domain ID:[ ]*(.+)/i,
  ],
  'status':	[
    /\[Status\]\s*(.+)/i,
    /Status\s*:\s?(.+)/i,
    /\[State\]\s*(.+)/i,
    /^state:\s*(.+)/i,
  ],
  'creation_date':	[
    /\[Created on\]\s*(.+)/i,
    /Created on[.]*: [a-zA-Z]+, (.+)/i,
    /Creation Date:\s?(.+)/i,
    /Creation date\s*:\s?(.+)/i,
    /Registration Date:\s?(.+)/i,
    /Created Date:\s?(.+)/i,
    /Created on:\s?(.+)/i,
    /Created on\s?[.]*:\s?(.+)\./i,
    /Date Registered\s?[.]*:\s?(.+)/i,
    /Domain Created\s?[.]*:\s?(.+)/i,
    /Domain registered\s?[.]*:\s?(.+)/i,
    /Domain record activated\s?[.]*:\s*?(.+)/i,
    /Record created on\s?[.]*:?\s*?(.+)/i,
    /Record created\s?[.]*:?\s*?(.+)/i,
    /Created\s?[.]*:?\s*?(.+)/i,
    /Registered on\s?[.]*:?\s*?(.+)/i,
    /Registered\s?[.]*:?\s*?(.+)/i,
    /Domain Create Date\s?[.]*:?\s*?(.+)/i,
    /Domain Registration Date\s?[.]*:?\s*?(.+)/i,
    /created:\s*(.+)/i,
    /\[Registered Date\]\s*(.+)/i,
    /created-date:\s*(.+)/i,
    /Domain Name Commencement Date: (.+)/i,
    /registered:\s*(.+)/i,
    /registration:\s*(.+)/i,
  ],
  'expiration_date':	[
    /\[Expires on\]/i,
    /Registrar Registration Expiration Date:[ ]*(.+)-[0-9]{4}/i,
    /Expires on[.]*: [a-zA-Z]+, (.+)/i,
    /Expiration Date:\s?(.+)/i,
    /Expiration date\s*:\s?(.+)/i,
    /Expires on:\s?(.+)/i,
    /Expires on\s?[.]*:\s?(.+)\./i,
    /Exp(?:iry)? Date\s?[.]*:\s?(.+)/i,
    /Expiry\s*:\s?(.+)/i,
    /Domain Currently Expires\s?[.]*:\s?(.+)/i,
    /Record will expire on\s?[.]*:\s?(.+)/i,
    /Domain expires\s?[.]*:\s*?(.+)/i,
    /Record expires on\s?[.]*:?\s*?(.+)/i,
    /Record expires\s?[.]*:?\s*?(.+)/i,
    /Expires\s?[.]*:?\s*?(.+)/i,
    /Expire Date\s?[.]*:?\s*?(.+)/i,
    /Expired\s?[.]*:?\s*?(.+)/i,
    /Domain Expiration Date\s?[.]*:?\s*?(.+)/i,
    /paid-till:\s*(.+)/i,
    /expiration_date:\s*(.+)/i,
    /expire-date:\s*(.+)/i,
    /renewal:\s*(.+)/i,
    /expire:\s*(.+)/i,
  ],
  'updated_date':	[
    /\[Last Updated\]\s*(.+)/i,
    /Record modified on[.]*: (.+) [a-zA-Z]+/i,
    /Record last updated on[.]*: [a-zA-Z]+, (.+)/i,
    /Updated Date:\s?(.+)/i,
    /Updated date\s*:\s?(.+)/i,
    /Record last updated on\s?[.]*:?\s?(.+)\./i,
    /Domain record last updated\s?[.]*:\s*?(.+)/i,
    /Domain Last Updated\s?[.]*:\s*?(.+)/i,
    /Last updated on:\s?(.+)/i,
    /Date Modified\s?[.]*:\s?(.+)/i,
    /Last Modified\s?[.]*:\s?(.+)/i,
    /Domain Last Updated Date\s?[.]*:\s?(.+)/i,
    /Record last updated\s?[.]*:\s?(.+)/i,
    /Modified\s?[.]*:\s?(.+)/i,
    /(?:C|c)hanged:\s*(.+)/i,
    /last_update:\s*(.+)/i,
    /Last Update\s?[.]*:\s?(.+)/i,
    /Last updated on (.+) [a-z]{3,4}/i,
    /Last updated:\s*(.+)/i,
    /last-updated:\s*(.+)/i,
    /\[Last Update\]\s*(.+) \([A-Z]+\)/i,
    /Last update of whois database:\s?[a-z]{3}, (.+) [a-z]{3,4}/i,
  ],
  'registrar': [
    /registrar:\s*(.+)/i,
    /Registrar:\s*(.+)/i,
    /Sponsoring Registrar Organization:\s*(.+)/i,
    /Registered through:\s?(.+)/i,
    /Registrar Name[.]*:\s?(.+)/i,
    /Record maintained by:\s?(.+)/i,
    /Registration Service Provided By:\s?(.+)/i,
    /Registrar of Record:\s?(.+)/i,
    /Domain Registrar :\s?(.+)/i,
    /Registration Service Provider: (.+)/i,
    /\tName:\t\s(.+)/i,
  ],
  'whois_server':	[
    /Whois Server:\s?(.+)/i,
    /Registrar Whois:\s?(.+)/i,
  ],
  'nameservers': [
    /Name Server:[ ]*([^ ]+)/i,
    /Nameservers:[ ]*([^ ]+)/i,
    /nameserver:\s*(.+)/i,
    /nserver:\s*([^[\s]+)/i,
    /Name Server[.]+ ([^[\s]+)/i,
    /Hostname:\s*([^\s]+)/i,
    /DNS[0-9]+:\s*(.+)/i,
    /   DNS:\s*(.+)/i,
    /ns[0-9]+:\s*(.+)/i,
    /NS [0-9]+\s*:\s*(.+)/i,
    /\[Name Server\]\s*(.+)/i,
    /Nserver:\s*(.+)/i,
  ],
  'emails':	[
    /([\w.-]+@[\w.-]+\.[\w]{2,6})/i,
    /([\w.-]+\sAT\s[\w.-]+\sDOT\s[\w]{2,6})/i,
  ],
};

const registrantPatterns = [
	"   Registrant:[ ]*\n      (?P<organization>.*)\n      (?P<name>.*)\n      (?P<street>.*)\n      (?P<city>.*), (?P<state>.*) (?P<postalcode>.*)\n      (?P<country>.*)\n(?:      Phone: (?P<phone>.*)\n)?      Email: (?P<email>.*)\n", // Corporate Domains, Inc.
	"Registrant:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n", // OVH
	"(?:Registrant ID:(?P<handle>.+)\n)?Registrant Name:(?P<name>.*)\n(?:Registrant Organization:(?P<organization>.*)\n)?Registrant Street1?:(?P<street1>.*)\n(?:Registrant Street2:(?P<street2>.*)\n)?(?:Registrant Street3:(?P<street3>.*)\n)?Registrant City:(?P<city>.*)\nRegistrant State/Province:(?P<state>.*)\nRegistrant Postal Code:(?P<postalcode>.*)\nRegistrant Country:(?P<country>.*)\nRegistrant Phone:(?P<phone>.*)\n(?:Registrant Phone Ext.:(?P<phone_ext>.*)\n)?(?:Registrant FAX:(?P<fax>.*)\n)?(?:Registrant FAX Ext.:(?P<fax_ext>.*)\n)?Registrant Email:(?P<email>.*)", // Public Interest Registry (.org), nic.pw, No-IP.com
	"Registrant ID:(?P<handle>.+)\nRegistrant Name:(?P<name>.*)\n(?:Registrant Organization:(?P<organization>.*)\n)?Registrant Address1?:(?P<street1>.*)\n(?:Registrant Address2:(?P<street2>.*)\n)?(?:Registrant Address3:(?P<street3>.*)\n)?Registrant City:(?P<city>.*)\nRegistrant State/Province:(?P<state>.*)\nRegistrant Country/Economy:(?P<country>.*)\nRegistrant Postal Code:(?P<postalcode>.*)\nRegistrant Phone:(?P<phone>.*)\n(?:Registrant Phone Ext.:(?P<phone_ext>.*)\n)?(?:Registrant FAX:(?P<fax>.*)\n)?(?:Registrant FAX Ext.:(?P<fax_ext>.*)\n)?Registrant E-mail:(?P<email>.*)", // .ME, DotAsia
	"Registrant ID:\s*(?P<handle>.+)\nRegistrant Name:\s*(?P<name>.+)\nRegistrant Organization:\s*(?P<organization>.*)\nRegistrant Address1:\s*(?P<street1>.+)\nRegistrant Address2:\s*(?P<street2>.*)\nRegistrant City:\s*(?P<city>.+)\nRegistrant State/Province:\s*(?P<state>.+)\nRegistrant Postal Code:\s*(?P<postalcode>.+)\nRegistrant Country:\s*(?P<country>.+)\nRegistrant Country Code:\s*(?P<country_code>.+)\nRegistrant Phone Number:\s*(?P<phone>.+)\nRegistrant Email:\s*(?P<email>.+)\n", // .CO Internet
	"Registrant Contact: (?P<handle>.+)\nRegistrant Organization: (?P<organization>.+)\nRegistrant Name: (?P<name>.+)\nRegistrant Street: (?P<street>.+)\nRegistrant City: (?P<city>.+)\nRegistrant Postal Code: (?P<postalcode>.+)\nRegistrant State: (?P<state>.+)\nRegistrant Country: (?P<country>.+)\nRegistrant Phone: (?P<phone>.*)\nRegistrant Phone Ext: (?P<phone_ext>.*)\nRegistrant Fax: (?P<fax>.*)\nRegistrant Fax Ext: (?P<fax_ext>.*)\nRegistrant Email: (?P<email>.*)\n", // Key-Systems GmbH
	"(?:Registrant ID:[ ]*(?P<handle>.*)\n)?Registrant Name:[ ]*(?P<name>.*)\n(?:Registrant Organization:[ ]*(?P<organization>.*)\n)?Registrant Street:[ ]*(?P<street1>.+)\n(?:Registrant Street:[ ]*(?P<street2>.+)\n)?(?:Registrant Street:[ ]*(?P<street3>.+)\n)?Registrant City:[ ]*(?P<city>.+)\nRegistrant State(?:\/Province)?:[ ]*(?P<state>.*)\nRegistrant Postal Code:[ ]*(?P<postalcode>.+)\nRegistrant Country:[ ]*(?P<country>.+)\n(?:Registrant Phone:[ ]*(?P<phone>.*)\n)?(?:Registrant Phone Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Registrant Fax:[ ]*(?P<fax>.*)\n)?(?:Registrant Fax Ext:[ ]*(?P<fax_ext>.*)\n)?(?:Registrant Email:[ ]*(?P<email>.+)\n)?", // WildWestDomains, GoDaddy, Namecheap/eNom, Ascio, Musedoma (.museum), EuroDNS, nic.ps
	"Registrant\n(?:    (?P<organization>.+)\n)?    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n", // internet.bs
	" Registrant Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)", // Whois.com
	"owner-id:[ ]*(?P<handle>.*)\n(?:owner-organization:[ ]*(?P<organization>.*)\n)?owner-name:[ ]*(?P<name>.*)\nowner-street:[ ]*(?P<street>.*)\nowner-city:[ ]*(?P<city>.*)\nowner-zip:[ ]*(?P<postalcode>.*)\nowner-country:[ ]*(?P<country>.*)\n(?:owner-phone:[ ]*(?P<phone>.*)\n)?(?:owner-fax:[ ]*(?P<fax>.*)\n)?owner-email:[ ]*(?P<email>.*)", // InterNetworX
	"Registrant:\n registrant_org: (?P<organization>.*)\n registrant_name: (?P<name>.*)\n registrant_email: (?P<email>.*)\n registrant_address: (?P<address>.*)\n registrant_city: (?P<city>.*)\n registrant_state: (?P<state>.*)\n registrant_zip: (?P<postalcode>.*)\n registrant_country: (?P<country>.*)\n registrant_phone: (?P<phone>.*)", // Bellnames
	"Holder of domain name:\n(?P<name>[\S\s]+)\n(?P<street>.+)\n(?P<postalcode>[A-Z0-9-]+)\s+(?P<city>.+)\n(?P<country>.+)\nContractual Language", // nic.ch
	"\n\n(?:Owner)?\s+: (?P<name>.*)\n(?:\s+: (?P<organization>.*)\n)?\s+: (?P<street>.*)\n\s+: (?P<city>.*)\n\s+: (?P<state>.*)\n\s+: (?P<country>.*)\n", // nic.io
	"Contact Information:\n\[Name\]\s*(?P<name>.*)\n\[Email\]\s*(?P<email>.*)\n\[Web Page\]\s*(?P<url>.*)\n\[Postal code\]\s*(?P<postalcode>.*)\n\[Postal Address\]\s*(?P<street1>.*)\n(?:\s+(?P<street2>.*)\n)?(?:\s+(?P<street3>.*)\n)?\[Phone\]\s*(?P<phone>.*)\n\[Fax\]\s*(?P<fax>.*)\n", // jprs.jp
	"g\. \[Organization\]               (?P<organization>.+)\n", // .co.jp registrations at jprs.jp
	"Registrant ID:(?P<handle>.*)\nRegistrant Name:(?P<name>.*)\n(?:Registrant Organization:(?P<organization>.*)\n)?Registrant Address1:(?P<street1>.*)\n(?:Registrant Address2:(?P<street2>.*)\n)?(?:Registrant Address3:(?P<street3>.*)\n)?Registrant City:(?P<city>.*)\n(?:Registrant State/Province:(?P<state>.*)\n)?(?:Registrant Postal Code:(?P<postalcode>.*)\n)?Registrant Country:(?P<country>.*)\nRegistrant Country Code:.*\nRegistrant Phone Number:(?P<phone>.*)\n(?:Registrant Facsimile Number:(?P<facsimile>.*)\n)?Registrant Email:(?P<email>.*)", // .US, .biz (NeuStar), .buzz, .moe (Interlink Co. Ltd.)
	"Registrant\n  Name:             (?P<name>.+)\n(?:  Organization:     (?P<organization>.+)\n)?  ContactID:        (?P<handle>.+)\n(?:  Address:          (?P<street1>.+)\n(?:                    (?P<street2>.+)\n(?:                    (?P<street3>.+)\n)?)?                    (?P<city>.+)\n                    (?P<postalcode>.+)\n                    (?P<state>.+)\n                    (?P<country>.+)\n)?(?:  Created:          (?P<creationdate>.+)\n)?(?:  Last Update:      (?P<changedate>.+)\n)?", // nic.it
	"  Organisation Name[.]* (?P<name>.*)\n  Organisation Address[.]* (?P<street1>.*)\n  Organisation Address[.]* (?P<street2>.*)\n(?:  Organisation Address[.]* (?P<street3>.*)\n)?  Organisation Address[.]* (?P<city>.*)\n  Organisation Address[.]* (?P<postalcode>.*)\n  Organisation Address[.]* (?P<state>.*)\n  Organisation Address[.]* (?P<country>.*)", // Melbourne IT (what a horrid format...)
	"Registrant:[ ]*(?P<name>.+)\n[\s\S]*Eligibility Name:[ ]*(?P<organization>.+)\n[\s\S]*Registrant Contact ID:[ ]*(?P<handle>.+)\n", // .au business
	"Eligibility Type:[ ]*Citizen\/Resident\n[\s\S]*Registrant Contact ID:[ ]*(?P<handle>.+)\n[\s\S]*Registrant Contact Name:[ ]*(?P<name>.+)\n", // .au individual
	"Registrant:[ ]*(?P<organization>.+)\n[\s\S]*Eligibility Type:[ ]*(Higher Education Institution|Company|Incorporated Association|Other)\n[\s\S]*Registrant Contact ID:[ ]*(?P<handle>.+)\n[\s\S]*Registrant Contact Name:[ ]*(?P<name>.+)\n", // .au educational, company, 'incorporated association' (non-profit?), other (spotted for linux.conf.au, unsure if also for others)
	"    Registrant:\n        (?P<name>.+)\n\n    Registrant type:\n        .*\n\n    Registrant's address:\n        The registrant .* opted to have", // Nominet (.uk) with hidden address
	"    Registrant:\n        (?P<name>.+)\n\n[\s\S]*    Registrant type:\n        .*\n\n    Registrant's address:\n        (?P<street1>.+)\n(?:        (?P<street2>.+)\n(?:        (?P<street3>.+)\n)??)??        (?P<city>[^0-9\n]+)\n(?:        (?P<state>.+)\n)?        (?P<postalcode>.+)\n        (?P<country>.+)\n\n", // Nominet (.uk) with visible address
	"Domain Owner:\n\t(?P<organization>.+)\n\n[\s\S]*?(?:Registrant Contact:\n\t(?P<name>.+))?\n\nRegistrant(?:'s)? (?:a|A)ddress:(?:\n\t(?P<street1>.+)\n(?:\t(?P<street2>.+)\n)?(?:\t(?P<street3>.+)\n)?\t(?P<city>.+)\n\t(?P<postalcode>.+))?\n\t(?P<country>.+)(?:\n\t(?P<phone>.+) \(Phone\)\n\t(?P<fax>.+) \(FAX\)\n\t(?P<email>.+))?\n\n", // .ac.uk - what a mess...
	"Registrant ID: (?P<handle>.+)\nRegistrant: (?P<name>.+)\nRegistrant Contact Email: (?P<email>.+)", // .cn (CNNIC)
	"Registrant contact:\n  (?P<name>.+)\n  (?P<street>.*)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n\n", // Fabulous.com
	"registrant-name:\s*(?P<name>.+)\nregistrant-type:\s*(?P<type>.+)\nregistrant-address:\s*(?P<street>.+)\nregistrant-postcode:\s*(?P<postalcode>.+)\nregistrant-city:\s*(?P<city>.+)\nregistrant-country:\s*(?P<country>.+)\n(?:registrant-phone:\s*(?P<phone>.+)\n)?(?:registrant-email:\s*(?P<email>.+)\n)?", // Hetzner
	"Registrant Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n", // GAL Communication
	"Contact Information : For Customer # [0-9]+[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n", // GAL Communication alternative (private WHOIS) format?
	"Registrant:\n   Name:           (?P<name>.+)\n   City:           (?P<city>.+)\n   State:          (?P<state>.+)\n   Country:        (?P<country>.+)\n", // Akky (.com.mx)
	"   Registrant:\n      (?P<name>.+)\n      (?P<street>.+)\n      (?P<city>.+) (?P<state>\S+),[ ]+(?P<postalcode>.+)\n      (?P<country>.+)", // .am
	"Domain Holder: (?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?, (?P<city>[^.,]+), (?P<district>.+), (?P<state>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n", // .co.th, format 1
	"Domain Holder: (?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?, (?P<city>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n", // .co.th, format 2
	"Domain Holder: (?P<organization>.+)\n(?P<street1>.+)\n(?:(?P<street2>.+)\n)?(?:(?P<street3>.+)\n)?.+?, (?P<district>.+)\n(?P<city>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n", // .co.th, format 3
	"Domain Holder: (?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?\n(?P<city>.+),? (?P<state>[A-Z]{2,3})(?: [A-Z0-9]+)?\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n", // .co.th, format 4
	"   Registrant:\n      (?P<organization>.+)\n      (?P<name>.+)  (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)\n      (?P<street>.*)\n      (?P<city>.+), (?P<state>[^,\n]*)\n      (?P<country>.+)\n", // .com.tw (Western registrars)
	"Registrant:\n(?P<organization1>.+)\n(?P<organization2>.+)\n(?P<street1>.+?)(?:,+(?P<street2>.+?)(?:,+(?P<street3>.+?)(?:,+(?P<street4>.+?)(?:,+(?P<street5>.+?)(?:,+(?P<street6>.+?)(?:,+(?P<street7>.+?))?)?)?)?)?)?,(?P<city>.+),(?P<country>.+)\n\n   Contact:\n      (?P<name>.+)   (?P<email>.+)\n      TEL:  (?P<phone>.+?)(?:(?:#|ext.?)(?P<phone_ext>.+))?\n      FAX:  (?P<fax>.+)(?:(?:#|ext.?)(?P<fax_ext>.+))?\n", // .com.tw (TWNIC/SEEDNET, Taiwanese companies only?)
	"Registrant Contact Information:\n\nCompany English Name \(It should be the same as the registered/corporation name on your Business Register Certificate or relevant documents\):(?P<organization1>.+)\nCompany Chinese name:(?P<organization2>.+)\nAddress: (?P<street>.+)\nCountry: (?P<country>.+)\nEmail: (?P<email>.+)\n", // HKDNR (.hk)
	"Registrant ID:(?P<handle>.+)\nRegistrant Name:(?P<name>.*)\n(?:Registrant Organization:(?P<organization>.*)\n)?Registrant Street1:(?P<street1>.+?)\n(?:Registrant Street2:(?P<street2>.+?)\n(?:Registrant Street3:(?P<street3>.+?)\n)?)?Registrant City:(?P<city>.+)\nRegistrant State:(?P<state>.*)\nRegistrant Postal Code:(?P<postalcode>.+)\nRegistrant Country:(?P<country>[A-Z]+)\nRegistrant Phone:(?P<phone>.*?)\nRegistrant Fax:(?P<fax>.*)\nRegistrant Email:(?P<email>.+)\n", // Realtime Register
	"owner:\s+(?P<name>.+)", // .br
	"person:\s+(?P<name>.+)", // nic.ru (person)
	"org:\s+(?P<organization>.+)", // nic.ru (organization)
];

const techContactPatterns = [
	"   Technical Contact:[ ]*\n      (?P<organization>.*)\n      (?P<name>.*)\n      (?P<street>.*)\n      (?P<city>.*), (?P<state>.*) (?P<postalcode>.*)\n      (?P<country>.*)\n(?:      Phone: (?P<phone>.*)\n)?      Email: (?P<email>.*)\n", //Corporate Domains, Inc.
	"Technical Contact:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n", //OVH
	"(?:Tech ID:(?P<handle>.+)\n)?Tech Name:(?P<name>.*)\n(:?Tech Organization:(?P<organization>.*)\n)?Tech Street1?:(?P<street1>.*)\n(?:Tech Street2:(?P<street2>.*)\n)?(?:Tech Street3:(?P<street3>.*)\n)?Tech City:(?P<city>.*)\nTech State/Province:(?P<state>.*)\nTech Postal Code:(?P<postalcode>.*)\nTech Country:(?P<country>.*)\nTech Phone:(?P<phone>.*)\n(?:Tech Phone Ext.:(?P<phone_ext>.*)\n)?(?:Tech FAX:(?P<fax>.*)\n)?(?:Tech FAX Ext.:(?P<fax_ext>.*)\n)?Tech Email:(?P<email>.*)", //Public Interest Registry (.org), nic.pw, No-IP.com
	"Tech(?:nical)? ID:(?P<handle>.+)\nTech(?:nical)? Name:(?P<name>.*)\n(?:Tech(?:nical)? Organization:(?P<organization>.*)\n)?Tech(?:nical)? Address1?:(?P<street1>.*)\n(?:Tech(?:nical)? Address2:(?P<street2>.*)\n)?(?:Tech(?:nical)? Address3:(?P<street3>.*)\n)?Tech(?:nical)? City:(?P<city>.*)\nTech(?:nical)? State/Province:(?P<state>.*)\nTech(?:nical)? Country/Economy:(?P<country>.*)\nTech(?:nical)? Postal Code:(?P<postalcode>.*)\nTech(?:nical)? Phone:(?P<phone>.*)\n(?:Tech(?:nical)? Phone Ext.:(?P<phone_ext>.*)\n)?(?:Tech(?:nical)? FAX:(?P<fax>.*)\n)?(?:Tech(?:nical)? FAX Ext.:(?P<fax_ext>.*)\n)?Tech(?:nical)? E-mail:(?P<email>.*)", //.ME, DotAsia
	"Technical Contact ID:\s*(?P<handle>.+)\nTechnical Contact Name:\s*(?P<name>.+)\nTechnical Contact Organization:\s*(?P<organization>.*)\nTechnical Contact Address1:\s*(?P<street1>.+)\nTechnical Contact Address2:\s*(?P<street2>.*)\nTechnical Contact City:\s*(?P<city>.+)\nTechnical Contact State/Province:\s*(?P<state>.+)\nTechnical Contact Postal Code:\s*(?P<postalcode>.+)\nTechnical Contact Country:\s*(?P<country>.+)\nTechnical Contact Country Code:\s*(?P<country_code>.+)\nTechnical Contact Phone Number:\s*(?P<phone>.+)\nTechnical Contact Email:\s*(?P<email>.+)\n", //.CO Internet
	"Tech Contact: (?P<handle>.+)\nTech Organization: (?P<organization>.+)\nTech Name: (?P<name>.+)\nTech Street: (?P<street>.+)\nTech City: (?P<city>.+)\nTech Postal Code: (?P<postalcode>.+)\nTech State: (?P<state>.+)\nTech Country: (?P<country>.+)\nTech Phone: (?P<phone>.*)\nTech Phone Ext: (?P<phone_ext>.*)\nTech Fax: (?P<fax>.*)\nTech Fax Ext: (?P<fax_ext>.*)\nTech Email: (?P<email>.*)\n", //Key-Systems GmbH
	"(?:Tech ID:[ ]*(?P<handle>.*)\n)?Tech[ ]*Name:[ ]*(?P<name>.*)\n(?:Tech[ ]*Organization:[ ]*(?P<organization>.*)\n)?Tech[ ]*Street:[ ]*(?P<street1>.+)\n(?:Tech[ ]*Street:[ ]*(?P<street2>.+)\n)?(?:Tech[ ]*Street:[ ]*(?P<street3>.+)\n)?Tech[ ]*City:[ ]*(?P<city>.+)\nTech[ ]*State(?:\/Province)?:[ ]*(?P<state>.*)\nTech[ ]*Postal[ ]*Code:[ ]*(?P<postalcode>.+)\nTech[ ]*Country:[ ]*(?P<country>.+)\n(?:Tech[ ]*Phone:[ ]*(?P<phone>.*)\n)?(?:Tech[ ]*Phone[ ]*Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Tech[ ]*Fax:[ ]*(?P<fax>.*)\n)?(?:Tech[ ]*Fax[ ]*Ext:\s*?(?P<fax_ext>.*)\n)?(?:Tech[ ]*Email:[ ]*(?P<email>.+)\n)?", //WildWestDomains, GoDaddy, Namecheap/eNom, Ascio, Musedoma (.museum), EuroDNS, nic.ps
	"Technical Contact\n(?:    (?P<organization>.+)\n)?    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n", //internet.bs
	" Technical Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)", //Whois.com
	"tech-id:[ ]*(?P<handle>.*)\n(?:tech-organization:[ ]*(?P<organization>.*)\n)?tech-name:[ ]*(?P<name>.*)\ntech-street:[ ]*(?P<street>.*)\ntech-city:[ ]*(?P<city>.*)\ntech-zip:[ ]*(?P<postalcode>.*)\ntech-country:[ ]*(?P<country>.*)\n(?:tech-phone:[ ]*(?P<phone>.*)\n)?(?:tech-fax:[ ]*(?P<fax>.*)\n)?tech-email:[ ]*(?P<email>.*)", //InterNetworX
	"Technical Contact:\n tech_org: (?P<organization>.*)\n tech_name: (?P<name>.*)\n tech_email: (?P<email>.*)\n tech_address: (?P<address>.*)\n tech_city: (?P<city>.*)\n tech_state: (?P<state>.*)\n tech_zip: (?P<postalcode>.*)\n tech_country: (?P<country>.*)\n tech_phone: (?P<phone>.*)", //Bellnames
	"Technical contact:\n(?P<name>[\S\s]+)\n(?P<street>.+)\n(?P<postalcode>[A-Z0-9-]+)\s+(?P<city>.+)\n(?P<country>.+)\n\n", //nic.ch
	"Tech Contact ID:[ ]*(?P<handle>.+)\nTech Contact Name:[ ]*(?P<name>.+)", //.au
	"Technical Contact ID:(?P<handle>.*)\nTechnical Contact Name:(?P<name>.*)\n(?:Technical Contact Organization:(?P<organization>.*)\n)?Technical Contact Address1:(?P<street1>.*)\n(?:Technical Contact Address2:(?P<street2>.*)\n)?(?:Technical Contact Address3:(?P<street3>.*)\n)?Technical Contact City:(?P<city>.*)\n(?:Technical Contact State/Province:(?P<state>.*)\n)?(?:Technical Contact Postal Code:(?P<postalcode>.*)\n)?Technical Contact Country:(?P<country>.*)\nTechnical Contact Country Code:.*\nTechnical Contact Phone Number:(?P<phone>.*)\n(?:Technical Contact Facsimile Number:(?P<facsimile>.*)\n)?Technical Contact Email:(?P<email>.*)", //.US, .biz (NeuStar), .buzz, .moe (Interlink Co. Ltd.)
	"Technical Contacts\n  Name:             (?P<name>.+)\n(?:  Organization:     (?P<organization>.+)\n)?  ContactID:        (?P<handle>.+)\n(?:  Address:          (?P<street1>.+)\n(?:                    (?P<street2>.+)\n(?:                    (?P<street3>.+)\n)?)?                    (?P<city>.+)\n                    (?P<postalcode>.+)\n                    (?P<state>.+)\n                    (?P<country>.+)\n)?(?:  Created:          (?P<creationdate>.+)\n)?(?:  Last Update:      (?P<changedate>.+)\n)?", //nic.it  //  NOTE: Why does this say 'Contacts'? Can it have multiple?
	"Tech Name[.]* (?P<name>.*)\n  Tech Address[.]* (?P<street1>.*)\n  Tech Address[.]* (?P<street2>.*)\n(?:  Tech Address[.]* (?P<street3>.*)\n)?  Tech Address[.]* (?P<city>.*)\n  Tech Address[.]* (?P<postalcode>.*)\n  Tech Address[.]* (?P<state>.*)\n  Tech Address[.]* (?P<country>.*)\n  Tech Email[.]* (?P<email>.*)\n  Tech Phone[.]* (?P<phone>.*)\n  Tech Fax[.]* (?P<fax>.*)", //Melbourne IT
	"Technical contact:\n(?:  (?P<organization>.+)\n)?  (?P<name>.+)\n  (?P<email>.+)\n  (?P<street>.+)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n  Phone: (?P<phone>.*)\n  Fax: (?P<fax>.*)\n", //Fabulous.com
	"tech-c-name:\s*(?P<name>.+)\ntech-c-type:\s*(?P<type>.+)\ntech-c-address:\s*(?P<street>.+)\ntech-c-postcode:\s*(?P<postalcode>.+)\ntech-c-city:\s*(?P<city>.+)\ntech-c-country:\s*(?P<country>.+)\n(?:tech-c-phone:\s*(?P<phone>.+)\n)?(?:tech-c-email:\s*(?P<email>.+)\n)?", //Hetzner
	"Admin Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n", //GAL Communication
	"   Technical contact:\n      (?P<name>.+)\n      (?P<organization>.*)\n      (?P<street>.+)\n      (?P<city>.+) (?P<state>\S+),[ ]+(?P<postalcode>.+)\n      (?P<country>.+)\n      (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)", //.am
	"Technical:\n\s*Name:\s*(?P<name>.*)\n\s*Organisation:\s*(?P<organization>.*)\n\s*Language:.*\n\s*Phone:\s*(?P<phone>.*)\n\s*Fax:\s*(?P<fax>.*)\n\s*Email:\s*(?P<email>.*)\n", //EURid
	"\\[Zone-C\\]\nType: (?P<type>.+)\nName: (?P<name>.+)\n(Organisation: (?P<organization>.+)\n){0,1}(Address: (?P<street1>.+)\n){1}(Address: (?P<street2>.+)\n){0,1}(Address: (?P<street3>.+)\n){0,1}(Address: (?P<street4>.+)\n){0,1}PostalCode: (?P<postalcode>.+)\nCity: (?P<city>.+)\nCountryCode: (?P<country>[A-Za-z]{2})\nPhone: (?P<phone>.+)\nFax: (?P<fax>.+)\nEmail: (?P<email>.+)\n(Remarks: (?P<remark>.+)\n){0,1}Changed: (?P<changed>.+)", //DeNIC
	"Technical Contact:\n   Name:           (?P<name>.+)\n   City:           (?P<city>.+)\n   State:          (?P<state>.+)\n   Country:        (?P<country>.+)\n", //Akky (.com.mx)
	"Tech Contact: (?P<handle>.+)\n(?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?\n(?P<city>.+),? (?P<state>[A-Z]{2,3})(?: [A-Z0-9]+)?\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n", //.co.th, format 1
	"Tech Contact: (?P<handle>.+)\n(?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?\n(?P<city>.+), (?P<state>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n", //.co.th, format 2
	"Tech Contact: (?P<handle>.+)\n(?P<organization>.+)\n(?P<street1>.+?)(?:,+ (?P<street2>.+?)(?:,+ (?P<street3>.+?)(?:,+ (?P<street4>.+?)(?:,+ (?P<street5>.+?)(?:,+ (?P<street6>.+?)(?:,+ (?P<street7>.+?))?)?)?)?)?)?, (?P<city>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n", //.co.th, format 3
	"Tech Contact: (?P<handle>.+)\n(?P<street1>.+) (?P<city>[^\s]+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n", //.co.th, format 4
	"Tech Contact: (?P<handle>.+)\n(?P<organization>.+)\n(?P<street1>.+)\n(?P<district>.+) (?P<city>[^\s]+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n", //.co.th, format 5
	"Tech Contact: (?P<handle>.+)\n(?P<organization>.+)\n(?P<street1>.+)\n(?P<street2>.+)\n(?:(?P<street3>.+)\n)?(?P<city>.+)\n(?P<postalcode>.+)\n(?P<country>[A-Z]+)\n", //.co.th, format 6
	"   Technical Contact:\n      (?P<name>.+)  (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)\n", //.com.tw (Western registrars)
	"Technical Contact Information:\n\n(?:Given name: (?P<firstname>.+)\n)?(?:Family name: (?P<lastname>.+)\n)?(?:Company name: (?P<organization>.+)\n)?Address: (?P<street>.+)\nCountry: (?P<country>.+)\nPhone: (?P<phone>.*)\nFax: (?P<fax>.*)\nEmail: (?P<email>.+)\n(?:Account Name: (?P<handle>.+)\n)?", //HKDNR (.hk)
	"TECH ID:(?P<handle>.+)\nTECH Name:(?P<name>.*)\n(?:TECH Organization:(?P<organization>.*)\n)?TECH Street1:(?P<street1>.+?)\n(?:TECH Street2:(?P<street2>.+?)\n(?:TECH Street3:(?P<street3>.+?)\n)?)?TECH City:(?P<city>.+)\nTECH State:(?P<state>.*)\nTECH Postal Code:(?P<postalcode>.+)\nTECH Country:(?P<country>[A-Z]+)\nTECH Phone:(?P<phone>.*?)\nTECH Fax:(?P<fax>.*)\nTECH Email:(?P<email>.+)\n", //Realtime Register
];

const adminContactPatterns = [
	"   Administrative Contact:[ ]*\n      (?P<organization>.*)\n      (?P<name>.*)\n      (?P<street>.*)\n      (?P<city>.*), (?P<state>.*) (?P<postalcode>.*)\n      (?P<country>.*)\n(?:      Phone: (?P<phone>.*)\n)?      Email: (?P<email>.*)\n", //Corporate Domains, Inc.
	"Administrative Contact:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n", //OVH
	"(?:Admin ID:(?P<handle>.+)\n)?Admin Name:(?P<name>.*)\n(?:Admin Organization:(?P<organization>.*)\n)?Admin Street1?:(?P<street1>.*)\n(?:Admin Street2:(?P<street2>.*)\n)?(?:Admin Street3:(?P<street3>.*)\n)?Admin City:(?P<city>.*)\nAdmin State/Province:(?P<state>.*)\nAdmin Postal Code:(?P<postalcode>.*)\nAdmin Country:(?P<country>.*)\nAdmin Phone:(?P<phone>.*)\n(?:Admin Phone Ext.:(?P<phone_ext>.*)\n)?(?:Admin FAX:(?P<fax>.*)\n)?(?:Admin FAX Ext.:(?P<fax_ext>.*)\n)?Admin Email:(?P<email>.*)", //Public Interest Registry (.org), nic.pw, No-IP.com
	"Admin(?:istrative)? ID:(?P<handle>.+)\nAdmin(?:istrative)? Name:(?P<name>.*)\n(?:Admin(?:istrative)? Organization:(?P<organization>.*)\n)?Admin(?:istrative)? Address1?:(?P<street1>.*)\n(?:Admin(?:istrative)? Address2:(?P<street2>.*)\n)?(?:Admin(?:istrative)? Address3:(?P<street3>.*)\n)?Admin(?:istrative)? City:(?P<city>.*)\nAdmin(?:istrative)? State/Province:(?P<state>.*)\nAdmin(?:istrative)? Country/Economy:(?P<country>.*)\nAdmin(?:istrative)? Postal Code:(?P<postalcode>.*)\nAdmin(?:istrative)? Phone:(?P<phone>.*)\n(?:Admin(?:istrative)? Phone Ext.:(?P<phone_ext>.*)\n)?(?:Admin(?:istrative)? FAX:(?P<fax>.*)\n)?(?:Admin(?:istrative)? FAX Ext.:(?P<fax_ext>.*)\n)?Admin(?:istrative)? E-mail:(?P<email>.*)", //.ME, DotAsia
	"Administrative Contact ID:\s*(?P<handle>.+)\nAdministrative Contact Name:\s*(?P<name>.+)\nAdministrative Contact Organization:\s*(?P<organization>.*)\nAdministrative Contact Address1:\s*(?P<street1>.+)\nAdministrative Contact Address2:\s*(?P<street2>.*)\nAdministrative Contact City:\s*(?P<city>.+)\nAdministrative Contact State/Province:\s*(?P<state>.+)\nAdministrative Contact Postal Code:\s*(?P<postalcode>.+)\nAdministrative Contact Country:\s*(?P<country>.+)\nAdministrative Contact Country Code:\s*(?P<country_code>.+)\nAdministrative Contact Phone Number:\s*(?P<phone>.+)\nAdministrative Contact Email:\s*(?P<email>.+)\n", //.CO Internet
	"Admin Contact: (?P<handle>.+)\nAdmin Organization: (?P<organization>.+)\nAdmin Name: (?P<name>.+)\nAdmin Street: (?P<street>.+)\nAdmin City: (?P<city>.+)\nAdmin State: (?P<state>.+)\nAdmin Postal Code: (?P<postalcode>.+)\nAdmin Country: (?P<country>.+)\nAdmin Phone: (?P<phone>.*)\nAdmin Phone Ext: (?P<phone_ext>.*)\nAdmin Fax: (?P<fax>.*)\nAdmin Fax Ext: (?P<fax_ext>.*)\nAdmin Email: (?P<email>.*)\n", //Key-Systems GmbH
	"(?:Admin ID:[ ]*(?P<handle>.*)\n)?Admin[ ]*Name:[ ]*(?P<name>.*)\n(?:Admin[ ]*Organization:[ ]*(?P<organization>.*)\n)?Admin[ ]*Street:[ ]*(?P<street1>.+)\n(?:Admin[ ]*Street:[ ]*(?P<street2>.+)\n)?(?:Admin[ ]*Street:[ ]*(?P<street3>.+)\n)?Admin[ ]*City:[ ]*(?P<city>.+)\nAdmin[ ]*State(?:\/Province)?:[ ]*(?P<state>.*)\nAdmin[ ]*Postal[ ]*Code:[ ]*(?P<postalcode>.+)\nAdmin[ ]*Country:[ ]*(?P<country>.+)\n(?:Admin[ ]*Phone:[ ]*(?P<phone>.*)\n)?(?:Admin[ ]*Phone[ ]*Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Admin[ ]*Fax:[ ]*(?P<fax>.*)\n)?(?:Admin[ ]*Fax[ ]*Ext:\s*?(?P<fax_ext>.*)\n)?(?:Admin[ ]*Email:[ ]*(?P<email>.+)\n)?", //WildWestDomains, GoDaddy, Namecheap/eNom, Ascio, Musedoma (.museum), EuroDNS, nic.ps
	"Administrative Contact\n(?:    (?P<organization>.+)\n)?    (?P<name>.+)\n    Email:(?P<email>.+)\n    (?P<street1>.+)\n(?:    (?P<street2>.+)\n)?    (?P<postalcode>.+) (?P<city>.+)\n    (?P<country>.+)\n    Tel: (?P<phone>.+)\n\n", //internet.bs
	" Administrative Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)", //Whois.com
	"admin-id:[ ]*(?P<handle>.*)\n(?:admin-organization:[ ]*(?P<organization>.*)\n)?admin-name:[ ]*(?P<name>.*)\nadmin-street:[ ]*(?P<street>.*)\nadmin-city:[ ]*(?P<city>.*)\nadmin-zip:[ ]*(?P<postalcode>.*)\nadmin-country:[ ]*(?P<country>.*)\n(?:admin-phone:[ ]*(?P<phone>.*)\n)?(?:admin-fax:[ ]*(?P<fax>.*)\n)?admin-email:[ ]*(?P<email>.*)", //InterNetworX
	"Administrative Contact:\n admin_org: (?P<organization>.*)\n admin_name: (?P<name>.*)\n admin_email: (?P<email>.*)\n admin_address: (?P<address>.*)\n admin_city: (?P<city>.*)\n admin_state: (?P<state>.*)\n admin_zip: (?P<postalcode>.*)\n admin_country: (?P<country>.*)\n admin_phone: (?P<phone>.*)", //Bellnames
	"Administrative Contact ID:(?P<handle>.*)\nAdministrative Contact Name:(?P<name>.*)\n(?:Administrative Contact Organization:(?P<organization>.*)\n)?Administrative Contact Address1:(?P<street1>.*)\n(?:Administrative Contact Address2:(?P<street2>.*)\n)?(?:Administrative Contact Address3:(?P<street3>.*)\n)?Administrative Contact City:(?P<city>.*)\n(?:Administrative Contact State/Province:(?P<state>.*)\n)?(?:Administrative Contact Postal Code:(?P<postalcode>.*)\n)?Administrative Contact Country:(?P<country>.*)\nAdministrative Contact Country Code:.*\nAdministrative Contact Phone Number:(?P<phone>.*)\n(?:Administrative Contact Facsimile Number:(?P<facsimile>.*)\n)?Administrative Contact Email:(?P<email>.*)", //.US, .biz (NeuStar), .buzz, .moe (Interlink Co. Ltd.)
	"Admin Contact\n  Name:             (?P<name>.+)\n(?:  Organization:     (?P<organization>.+)\n)?  ContactID:        (?P<handle>.+)\n(?:  Address:          (?P<street1>.+)\n(?:                    (?P<street2>.+)\n(?:                    (?P<street3>.+)\n)?)?                    (?P<city>.+)\n                    (?P<postalcode>.+)\n                    (?P<state>.+)\n                    (?P<country>.+)\n)?(?:  Created:          (?P<creationdate>.+)\n)?(?:  Last Update:      (?P<changedate>.+)\n)?", //nic.it
	"Admin Name[.]* (?P<name>.*)\n  Admin Address[.]* (?P<street1>.*)\n  Admin Address[.]* (?P<street2>.*)\n(?:  Admin Address[.]* (?P<street3>.*)\n)?  Admin Address[.]* (?P<city>.*)\n  Admin Address[.]* (?P<postalcode>.*)\n  Admin Address[.]* (?P<state>.*)\n  Admin Address[.]* (?P<country>.*)\n  Admin Email[.]* (?P<email>.*)\n  Admin Phone[.]* (?P<phone>.*)\n  Admin Fax[.]* (?P<fax>.*)", //Melbourne IT
	"Administrative contact:\n(?:  (?P<organization>.+)\n)?  (?P<name>.+)\n  (?P<email>.+)\n  (?P<street>.+)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n  Phone: (?P<phone>.*)\n  Fax: (?P<fax>.*)\n", //Fabulous.com
	"admin-c-name:\s*(?P<name>.+)\nadmin-c-type:\s*(?P<type>.+)\nadmin-c-address:\s*(?P<street>.+)\nadmin-c-postcode:\s*(?P<postalcode>.+)\nadmin-c-city:\s*(?P<city>.+)\nadmin-c-country:\s*(?P<country>.+)\n(?:admin-c-phone:\s*(?P<phone>.+)\n)?(?:admin-c-email:\s*(?P<email>.+)\n)?", //Hetzner
	"Tech Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n", //GAL Communication
	"   Administrative contact:\n      (?P<name>.+)\n      (?P<organization>.*)\n      (?P<street>.+)\n      (?P<city>.+) (?P<state>\S+),[ ]+(?P<postalcode>.+)\n      (?P<country>.+)\n      (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)", //.am
	"Administrative Contact:\n   Name:           (?P<name>.+)\n   City:           (?P<city>.+)\n   State:          (?P<state>.+)\n   Country:        (?P<country>.+)\n", //Akky (.com.mx)
	"\\[Tech-C\\]\nType: (?P<type>.+)\nName: (?P<name>.+)\n(Organisation: (?P<organization>.+)\n){0,1}(Address: (?P<street1>.+)\n){1}(Address: (?P<street2>.+)\n){0,1}(Address: (?P<street3>.+)\n){0,1}(Address: (?P<street4>.+)\n){0,1}PostalCode: (?P<postalcode>.+)\nCity: (?P<city>.+)\nCountryCode: (?P<country>[A-Za-z]{2})\nPhone: (?P<phone>.+)\nFax: (?P<fax>.+)\nEmail: (?P<email>.+)\n(Remarks: (?P<remark>.+)\n){0,1}Changed: (?P<changed>.+)", //DeNIC
	"   Administrative Contact:\n      (?P<name>.+)  (?P<email>.+)\n      (?P<phone>.*)\n      (?P<fax>.*)\n", //.com.tw (Western registrars)
	"Administrative Contact Information:\n\n(?:Given name: (?P<firstname>.+)\n)?(?:Family name: (?P<lastname>.+)\n)?(?:Company name: (?P<organization>.+)\n)?Address: (?P<street>.+)\nCountry: (?P<country>.+)\nPhone: (?P<phone>.*)\nFax: (?P<fax>.*)\nEmail: (?P<email>.+)\n(?:Account Name: (?P<handle>.+)\n)?", //HKDNR (.hk)
	"ADMIN ID:(?P<handle>.+)\nADMIN Name:(?P<name>.*)\n(?:ADMIN Organization:(?P<organization>.*)\n)?ADMIN Street1:(?P<street1>.+?)\n(?:ADMIN Street2:(?P<street2>.+?)\n(?:ADMIN Street3:(?P<street3>.+?)\n)?)?ADMIN City:(?P<city>.+)\nADMIN State:(?P<state>.*)\nADMIN Postal Code:(?P<postalcode>.+)\nADMIN Country:(?P<country>[A-Z]+)\nADMIN Phone:(?P<phone>.*?)\nADMIN Fax:(?P<fax>.*)\nADMIN Email:(?P<email>.+)\n", //Realtime Register
];

const billingContactPatterns = [
	"(?:Billing ID:(?P<handle>.+)\n)?Billing Name:(?P<name>.*)\nBilling Organization:(?P<organization>.*)\nBilling Street1:(?P<street1>.*)\n(?:Billing Street2:(?P<street2>.*)\n)?(?:Billing Street3:(?P<street3>.*)\n)?Billing City:(?P<city>.*)\nBilling State/Province:(?P<state>.*)\nBilling Postal Code:(?P<postalcode>.*)\nBilling Country:(?P<country>.*)\nBilling Phone:(?P<phone>.*)\n(?:Billing Phone Ext.:(?P<phone_ext>.*)\n)?(?:Billing FAX:(?P<fax>.*)\n)?(?:Billing FAX Ext.:(?P<fax_ext>.*)\n)?Billing Email:(?P<email>.*)", //nic.pw, No-IP.com
	"Billing ID:(?P<handle>.+)\nBilling Name:(?P<name>.*)\n(?:Billing Organization:(?P<organization>.*)\n)?Billing Address1?:(?P<street1>.*)\n(?:Billing Address2:(?P<street2>.*)\n)?(?:Billing Address3:(?P<street3>.*)\n)?Billing City:(?P<city>.*)\nBilling State/Province:(?P<state>.*)\nBilling Country/Economy:(?P<country>.*)\nBilling Postal Code:(?P<postalcode>.*)\nBilling Phone:(?P<phone>.*)\n(?:Billing Phone Ext.:(?P<phone_ext>.*)\n)?(?:Billing FAX:(?P<fax>.*)\n)?(?:Billing FAX Ext.:(?P<fax_ext>.*)\n)?Billing E-mail:(?P<email>.*)", //DotAsia
	"Billing Contact ID:\s*(?P<handle>.+)\nBilling Contact Name:\s*(?P<name>.+)\nBilling Contact Organization:\s*(?P<organization>.*)\nBilling Contact Address1:\s*(?P<street1>.+)\nBilling Contact Address2:\s*(?P<street2>.*)\nBilling Contact City:\s*(?P<city>.+)\nBilling Contact State/Province:\s*(?P<state>.+)\nBilling Contact Postal Code:\s*(?P<postalcode>.+)\nBilling Contact Country:\s*(?P<country>.+)\nBilling Contact Country Code:\s*(?P<country_code>.+)\nBilling Contact Phone Number:\s*(?P<phone>.+)\nBilling Contact Email:\s*(?P<email>.+)\n", //.CO Internet
	"Billing Contact: (?P<handle>.+)\nBilling Organization: (?P<organization>.+)\nBilling Name: (?P<name>.+)\nBilling Street: (?P<street>.+)\nBilling City: (?P<city>.+)\nBilling Postal Code: (?P<postalcode>.+)\nBilling State: (?P<state>.+)\nBilling Country: (?P<country>.+)\nBilling Phone: (?P<phone>.*)\nBilling Phone Ext: (?P<phone_ext>.*)\nBilling Fax: (?P<fax>.*)\nBilling Fax Ext: (?P<fax_ext>.*)\nBilling Email: (?P<email>.*)\n", //Key-Systems GmbH
	"(?:Billing ID:[ ]*(?P<handle>.*)\n)?Billing[ ]*Name:[ ]*(?P<name>.*)\n(?:Billing[ ]*Organization:[ ]*(?P<organization>.*)\n)?Billing[ ]*Street:[ ]*(?P<street1>.+)\n(?:Billing[ ]*Street:[ ]*(?P<street2>.+)\n)?Billing[ ]*City:[ ]*(?P<city>.+)\nBilling[ ]*State\/Province:[ ]*(?P<state>.+)\nBilling[ ]*Postal[ ]*Code:[ ]*(?P<postalcode>.+)\nBilling[ ]*Country:[ ]*(?P<country>.+)\n(?:Billing[ ]*Phone:[ ]*(?P<phone>.*)\n)?(?:Billing[ ]*Phone[ ]*Ext:[ ]*(?P<phone_ext>.*)\n)?(?:Billing[ ]*Fax:[ ]*(?P<fax>.*)\n)?(?:Billing[ ]*Fax[ ]*Ext:\s*?(?P<fax_ext>.*)\n)?(?:Billing[ ]*Email:[ ]*(?P<email>.+)\n)?", //Musedoma (.museum)
	"Billing Contact:\n  (?P<name>.+)\n  (?P<street1>.+)\n(?:  (?P<street2>.*)\n)?(?:  (?P<street3>.*)\n)?  (?P<postalcode>.+), (?P<city>.+)\n  (?P<country>.+)\n  (?P<phone>.+)\n  (?P<email>.+)\n\n", //OVH
	" Billing Contact Details:[ ]*\n    (?P<organization>.*)\n    (?P<name>.*)[ ]{2,}\((?P<email>.*)\)\n    (?P<street1>.*)\n(?:    (?P<street2>.*)\n)?(?:    (?P<street3>.*)\n)?    (?P<city>.*)\n    (?P<state>.*),(?P<postalcode>.*)\n    (?P<country>.*)\n    Tel. (?P<phone>.*)", //Whois.com
	"billing-id:[ ]*(?P<handle>.*)\n(?:billing-organization:[ ]*(?P<organization>.*)\n)?billing-name:[ ]*(?P<name>.*)\nbilling-street:[ ]*(?P<street>.*)\nbilling-city:[ ]*(?P<city>.*)\nbilling-zip:[ ]*(?P<postalcode>.*)\nbilling-country:[ ]*(?P<country>.*)\n(?:billing-phone:[ ]*(?P<phone>.*)\n)?(?:billing-fax:[ ]*(?P<fax>.*)\n)?billing-email:[ ]*(?P<email>.*)", //InterNetworX
	"Billing Contact:\n bill_org: (?P<organization>.*)\n bill_name: (?P<name>.*)\n bill_email: (?P<email>.*)\n bill_address: (?P<address>.*)\n bill_city: (?P<city>.*)\n bill_state: (?P<state>.*)\n bill_zip: (?P<postalcode>.*)\n bill_country: (?P<country>.*)\n bill_phone: (?P<phone>.*)", //Bellnames
	"Billing Contact ID:(?P<handle>.*)\nBilling Contact Name:(?P<name>.*)\n(?:Billing Contact Organization:(?P<organization>.*)\n)?Billing Contact Address1:(?P<street1>.*)\n(?:Billing Contact Address2:(?P<street2>.*)\n)?(?:Billing Contact Address3:(?P<street3>.*)\n)?Billing Contact City:(?P<city>.*)\n(?:Billing Contact State/Province:(?P<state>.*)\n)?(?:Billing Contact Postal Code:(?P<postalcode>.*)\n)?Billing Contact Country:(?P<country>.*)\nBilling Contact Country Code:.*\nBilling Contact Phone Number:(?P<phone>.*)\n(?:Billing Contact Facsimile Number:(?P<facsimile>.*)\n)?Billing Contact Email:(?P<email>.*)", //.US, .biz (NeuStar), .buzz, .moe (Interlink Co. Ltd.)
	"Billing contact:\n(?:  (?P<organization>.+)\n)?  (?P<name>.+)\n  (?P<email>.+)\n  (?P<street>.+)\n  (?P<city>.+), (?P<state>.+) (?P<postalcode>.+) (?P<country>.+)\n  Phone: (?P<phone>.*)\n  Fax: (?P<fax>.*)\n", //Fabulous.com
	"Billing Contact Information :[ ]*\n[ ]+(?P<firstname>.*)\n[ ]+(?P<lastname>.*)\n[ ]+(?P<organization>.*)\n[ ]+(?P<email>.*)\n[ ]+(?P<street>.*)\n[ ]+(?P<city>.*)\n[ ]+(?P<postalcode>.*)\n[ ]+(?P<phone>.*)\n[ ]+(?P<fax>.*)\n\n", //GAL Communication
	"Billing Contact:\n   Name:           (?P<name>.+)\n   City:           (?P<city>.+)\n   State:          (?P<state>.+)\n   Country:        (?P<country>.+)\n", //Akky (.com.mx)
	"BILLING ID:(?P<handle>.+)\nBILLING Name:(?P<name>.*)\n(?:BILLING Organization:(?P<organization>.*)\n)?BILLING Street1:(?P<street1>.+?)\n(?:BILLING Street2:(?P<street2>.+?)\n(?:BILLING Street3:(?P<street3>.+?)\n)?)?BILLING City:(?P<city>.+)\nBILLING State:(?P<state>.*)\nBILLING Postal Code:(?P<postalcode>.+)\nBILLING Country:(?P<country>[A-Z]+)\nBILLING Phone:(?P<phone>.*?)\nBILLING Fax:(?P<fax>.*)\nBILLING Email:(?P<email>.+)\n", //Realtime Register
];

const contanctAttributes = ['name', 'handle', 'email', 'phone', 'fax', 'organization', 'country',
'city', 'state','postalcode', 'district', 'street', 'street1', 'street2', 'street3'];

const registrantXRegexes = registrantPatterns.map((pattern) => XRegExp(pattern));
const techContactXRegexes = techContactPatterns.map((pattern) => XRegExp(pattern));
const adminContactXRegexes = adminContactPatterns.map((pattern) => XRegExp(pattern));
const billingContactXRegexes = billingContactPatterns.map((pattern) => XRegExp(pattern));

const extractContact = (data, xRegexes) => {
  const result = {};
  for (let i = 0; i < xRegexes.length; i++) {
    let match = XRegExp.exec(data, xRegexes[i]);
    if (match) {
      contanctAttributes.map((attr) => {
        if (match[attr]) {
          result[attr] = match[attr].trim();
        }
      });
      break;
    }
  }
  return result;
}

const parse = (data) => {
  const result = {};

  if (data) {
    data.split("\n").forEach((line) => {
      Object.keys(grammarRegexes).forEach((key) => {
        for (let i = 0; i < grammarRegexes[key].length; i++) {
          let match = grammarRegexes[key][i].exec(line);
          if (match) {
            result[key] = match[1].trim();
            break;
          }
        }
      });
    });

    result['contact'] = {
      registrant: extractContact(data, registrantXRegexes),
      technical: extractContact(data, techContactXRegexes),
      admin: extractContact(data, adminContactXRegexes),
      billing: extractContact(data, billingContactXRegexes),
    };
  }

  return result;
}

module.exports = {
  parse
}
