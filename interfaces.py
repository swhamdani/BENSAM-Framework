# File: src/my_framework/interfaces.py

"""
This module defines the abstract base classes (ABCs) for the framework's core components.
By depending on these abstractions, the high-level logic remains independent of
the concrete implementations, making the framework extensible and loosely coupled.
"""

from abc import ABC, abstractmethod

class IDataSource(ABC):
    """
    Abstract base class for data sources.
    Defines the contract for retrieving data.
    """
    @abstractmethod
    def get_data(self):
        """
        Retrieves data from a source.
        Returns:
            Any: The data payload.
        """
        pass

class IProcessor(ABC):
    """
    Abstract base class for data processors.
    Defines the contract for transforming data.
    """
    @abstractmethod
    def process_data(self, data):
        """
        Performs a transformation on the input data.
        Args:
            data (Any): The input data.
        Returns:
            Any: The transformed data.
        """
        pass

class IDataSink(ABC):
    """
    Abstract base class for data sinks.
    Defines the contract for loading data to a destination.
    """
    @abstractmethod
    def load_data(self, data):
        """
        Loads data to a destination.
        Args:
            data (Any): The data to be loaded.
        """
        pass