"""Errors whose messages are intentionally safe to return to policy authors."""


class StandardsValidationError(ValueError):
    def __init__(self, public_message):
        self.public_message = public_message
        super().__init__(public_message)
