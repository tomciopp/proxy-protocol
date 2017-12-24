defmodule ProxyProtocol do
  @moduledoc """
  Documentation for ProxyProtocol.
  """

  defstruct [:dest_address, :dest_port, :inet, :src_address, :src_port, :version]

  def parse(<<"\n\r\n\r\0\n\rQUIT\n", _ :: binary>> = packet) do
    ProxyProtocol.V2.Parser.parse(packet)
  end

  defp parse(<<"PROXY TCP4 ", _ :: binary>> = packet) do
    ProxyProtocol.V1.Parser.parse(packet)
  end

  defp parse(<<"PROXY TCP6 ", _ :: binary>> = packet) do
    ProxyProtocol.V1.Parser.parse(packet)
  end

  defp parse(<<"PROXY UNKNOWN ", _ :: binary>> = packet) do
    ProxyProtocol.V1.Parser.parse(packet)
  end

  defp parse(<<"PROXY UNKNOWN\r\n">> = packet) do
    ProxyProtocol.V1.Parser.parse(packet)
  end

  defp parse(packet) do
    {:ok, %{ buffer: packet, proxy: %ProxyProtocol{} }}
  end
end
