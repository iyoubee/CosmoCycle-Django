from rolepermissions.roles import AbstractUserRole

class commonUser(AbstractUserRole):
    available_permissions = {
    }

class superUser(AbstractUserRole):
    available_permissions = {
    }