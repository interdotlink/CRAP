from __future__ import annotations

from typing import Optional, Union

from scapy.packet import Packet  # type: ignore


class BaseHeader:
    """
    Base class for all frames.
    This is a doubly-linked list so that each protocol header knows which
    protocol is above it / below it in the header stack.
    """

    # Protocol header under this protocol header, going down the OSI stack
    child: Optional[BaseHeader] = None

    # The scapy object for this protocol header
    data: Optional[Union[Packet, bytes]] = None

    # The scapy object stack for the entire header stack
    data_stack: Packet

    # libpcap filter for this protocol header
    filter: str = ""

    # libpcap filter for the entire header stack
    filter_stack: str = ""

    # Protocol header on top of this protocol header, going up the OSI stack
    parent: Optional[BaseHeader] = None

    def __len__(self: BaseHeader) -> int:
        if self.data:
            return len(self.data)
        else:
            return 0

    def build(self: BaseHeader) -> None:
        """
        Build up the packet data and filter string for the entire protocol
        header stack
        """
        header = self.get_bottom_header()
        if isinstance(header.data, Packet):
            self.data_stack = header.data.copy()
        else:
            self.data_stack = header.data
        self.set_filter_stack(header.filter)
        while header.parent != None:
            if header.parent:
                if isinstance(header.parent.data, Packet):
                    self.data_stack.add_payload(header.parent.data.copy())
                else:
                    self.data_stack.add_payload(header.parent.data)
                self.set_filter_stack(
                    self.get_filter_stack() + header.parent.filter
                )
                header = header.parent
            else:
                raise ValueError(f"{self} parent is undefined")

    def get_bottom_header(self: BaseHeader) -> BaseHeader:
        """
        Return the bottom header in the header stack
        """
        if not self.child:
            return self

        header = self.child
        while header.child:
            header = header.child
        return header

    def get_filter(self: BaseHeader) -> str:
        """
        Return the libpcap filter for the current header in the stack
        """
        return self.filter

    def get_filter_stack(self: BaseHeader) -> str:
        """
        Return the libpcap filter for the entire header stack
        """
        return self.filter_stack

    def get_packet(self: BaseHeader) -> Packet:
        return self.data_stack

    def get_packet_string(self: BaseHeader) -> str:
        header = self.get_bottom_header()
        output_data = f"{header.data!r} "
        parent = header.parent
        while parent:
            output_data += f"{parent.data!r} "
            parent = parent.parent
        return output_data

    def get_stack_length(self: BaseHeader) -> int:
        """
        Get the length (size) of the full header stack
        """
        header = self.get_bottom_header()
        length = len(header)
        while header.parent:
            length += len(header.parent)
            header = header.parent
        return length

    def insert_at_bottom(self: BaseHeader, header: BaseHeader) -> None:
        """
        Insert a new protocol header at the bottom of the stack
        """
        bottom = self.get_bottom_header()
        bottom.child = header
        header.parent = bottom

    def rebuild(self: BaseHeader) -> None:
        """
        Rebuild the entire stack in case any settings have changed
        """
        self.set_parent(None)
        self.set_child(None)
        self.__init__()  # type: ignore[misc]

    def set_child(self: BaseHeader, child: Optional[BaseHeader]) -> None:
        """
        Set the child for this header in the stack
        """
        self.child = child

    def set_filter(self: BaseHeader, filter: str) -> None:
        """
        Set the filter for the current header in the stack
        """
        self.filter = filter

    def set_filter_stack(self: BaseHeader, filter: str) -> None:
        """
        Set the filter for the entire header stack
        """
        self.filter_stack = filter

    def set_parent(self: BaseHeader, parent: Optional[BaseHeader]) -> None:
        """
        Set the parent for this header in the stack
        """
        self.parent = parent
