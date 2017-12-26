defmodule ProxyProtocol do
  @moduledoc """
  Handles parsing either v1 or v2 of the proxy protocol
  """

  defstruct [:dest_address, :dest_port, :inet, :src_address, :src_port, :version]

  def parse(<<"\n\r\n\r\0\n\rQUIT\n", _ :: binary>> = packet) do
    ProxyProtocol.V2.Parser.parse(packet)
  end

  def parse(<<"PROXY TCP4 ", _ :: binary>> = packet) do
    ProxyProtocol.V1.Parser.parse(packet)
  end

  def parse(<<"PROXY TCP6 ", _ :: binary>> = packet) do
    ProxyProtocol.V1.Parser.parse(packet)
  end

  def parse(<<"PROXY UNKNOWN ", _ :: binary>> = packet) do
    ProxyProtocol.V1.Parser.parse(packet)
  end

  def parse(<<"PROXY UNKNOWN\r\n">> = packet) do
    ProxyProtocol.V1.Parser.parse(packet)
  end

  def parse(packet) do
    {:ok, %{ buffer: packet, proxy: %ProxyProtocol{} }}
  end
end
