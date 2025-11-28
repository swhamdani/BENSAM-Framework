# interfaces.py
from abc import ABC, abstractmethod

class IBlockchainLogger(ABC):
    @abstractmethod
    def log_event(self, event_type, data):
        pass

class IDatabase(ABC):
    @abstractmethod
    def add_device(self, device):
        pass

    @abstractmethod
    def update_timestamp(self, name):
        pass

    @abstractmethod
    def store_profile(self, profile):
        pass

    @abstractmethod
    def log_traffic(self, packet):
        pass

    @abstractmethod
    def log_violation(self, device, violation):
        pass
