from enum import Enum


class EntityType(str, Enum):
    NAME = "NAME"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SSN = "SSN"
    PASSPORT = "PASSPORT"
    DRIVERS_LICENSE = "DRIVERS_LICENSE"
    DATE_OF_BIRTH = "DOB"
    CREDIT_CARD = "CREDIT_CARD"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    ROUTING_NUMBER = "ROUTING_NUMBER"
    MRN = "MRN"
    NPI = "NPI"
    DEA = "DEA"
    IP_ADDRESS = "IP_ADDRESS"
    MAC_ADDRESS = "MAC_ADDRESS"
    API_KEY = "API_KEY"
    JWT = "JWT"
    PASSWORD = "PASSWORD"
    ADDRESS = "ADDRESS"
    ZIP_CODE = "ZIP_CODE"
    COORDINATES = "COORDINATES"


PRESETS: dict[str, set[EntityType]] = {
    "hipaa": {
        EntityType.NAME, EntityType.EMAIL, EntityType.PHONE, EntityType.SSN,
        EntityType.DATE_OF_BIRTH, EntityType.ADDRESS, EntityType.ZIP_CODE,
        EntityType.MRN, EntityType.NPI, EntityType.DEA, EntityType.IP_ADDRESS,
    },
    "gdpr": {
        EntityType.NAME, EntityType.EMAIL, EntityType.PHONE, EntityType.SSN,
        EntityType.PASSPORT, EntityType.DATE_OF_BIRTH, EntityType.ADDRESS,
        EntityType.ZIP_CODE, EntityType.IP_ADDRESS, EntityType.COORDINATES,
        EntityType.BANK_ACCOUNT,
    },
    "pci": {
        EntityType.CREDIT_CARD, EntityType.BANK_ACCOUNT, EntityType.ROUTING_NUMBER,
        EntityType.NAME, EntityType.EMAIL, EntityType.PHONE,
        EntityType.ADDRESS, EntityType.ZIP_CODE,
    },
    "default": {
        EntityType.NAME, EntityType.EMAIL, EntityType.PHONE, EntityType.SSN,
        EntityType.CREDIT_CARD, EntityType.IP_ADDRESS, EntityType.DATE_OF_BIRTH,
        EntityType.API_KEY, EntityType.JWT,
    },
}
