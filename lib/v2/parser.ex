defmodule ProxyProtocol.V2.Parser do
  @moduledoc """
  Handles the binary version of the proxy protocol as defined in section 2.2:
  https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

  We are able to directly parse the binary by extracting the relevant sections
  piece by piece as specified by the protocol

  For protocols that we don't understand we return 'UNSPECIFIED'
  and the buffer

  """

  @signature <<"\n\r\n\r\0\n\rQUIT\n">>

  @unspec   @signature <> <<0>>
  @tcp_ipv4 @signature <> <<17>>
  @udp_ipv4 @signature <> <<18>>
  @tcp_ipv6 @signature <> <<33>>
  @udp_ipv6 @signature <> <<34>>
  @stream   @signature <> <<49>>
  @datagram @signature <> <<50>>

  @hex_table ~w(0 1 2 3 4 5 6 7 8 9 a b c d e f)
  @parse_error "Binary does not match proxy protocol signature"

  def parse(<<@tcp_ipv4, _len :: size(16), rest :: binary>>), do: parse_ipv4(rest)
  def parse(<<@udp_ipv4, _len :: size(16), rest :: binary>>), do: parse_ipv4(rest)
  def parse(<<@tcp_ipv6, _len :: size(16), rest :: binary>>), do: parse_ipv6(rest)
  def parse(<<@udp_ipv6, _len :: size(16), rest :: binary>>), do: parse_ipv6(rest)
  def parse(<<@stream,   _len :: size(16), rest :: binary>>), do: parse_unix(rest)
  def parse(<<@datagram, _len :: size(16), rest :: binary>>), do: parse_unix(rest)

  def parse(<<@unspec, len :: binary-size(2), rest :: binary>>) do
    parse(uint16(len), rest)
  end

  def parse(<<@signature, _ :: size(8), len :: binary-size(2), rest :: binary>>) do
    parse(uint16(len), rest)
  end

  def parse(other), do: {:error, %{ buffer: other, reason: @parse_error }}

  # Skip over any address bits and just return the buffer
  defp parse(address, rest) do
    <<_skip :: binary-size(address), buffer :: binary>> = rest

    success(buffer, %ProxyProtocol{
      inet: "UNSPECIFIED",
      version: "2"
    })
  end

  defp parse_ipv4(<<src_addr :: binary-size(4), dest_addr :: binary-size(4),
    src_port :: binary-size(2), dest_port :: binary-size(2), buffer :: binary>>) do

    success(buffer, %ProxyProtocol{
      dest_address: ipv4(dest_addr),
      dest_port: uint16(dest_port),
      inet: "TCP4",
      src_address: ipv4(src_addr),
      src_port: uint16(src_port),
      version: "2"
    })
  end

  def parse_ipv6(<<src_addr :: binary-size(16), dest_addr :: binary-size(16),
    src_port :: binary-size(2), dest_port :: binary-size(2), buffer :: binary>>) do

    success(buffer, %ProxyProtocol{
      dest_address: ipv6(dest_addr),
      dest_port: uint16(dest_port),
      inet: "TCP6",
      src_address: ipv6(src_addr),
      src_port: uint16(src_port),
      version: "2"
    })
  end

  def parse_unix(<<src_addr :: binary-size(108), dest_addr :: binary-size(108),
    buffer :: binary>>) do

    success(buffer, %ProxyProtocol{
      dest_address: socket(dest_addr),
      inet: "AF_UNIX",
      src_address: socket(src_addr),
      version: "2"
    })
  end

  defp success(buffer, proxy), do: {:ok, %{ buffer: buffer, proxy: proxy }}

  defp uint16(<<first, second>>), do: first * 256 + second

  defp ipv4(<<one, two, three, four>>), do: "#{one}.#{two}.#{three}.#{four}"
  defp ipv6(binary), do: ipv6(binary, [])
  defp ipv6(<<>>, acc) do
    acc
    |> Enum.reverse()
    |> Enum.chunk_every(4)
    |> Enum.map_join(":", &(Enum.join(&1)))
  end

  defp ipv6(<<upper :: size(4), lower :: size(4), rest :: binary>>, acc) do
    ipv6(rest, [Enum.at(@hex_table, lower), Enum.at(@hex_table, upper) | acc])
  end

  defp socket(<<0, _abstract :: binary>> = address), do: address
  defp socket(pathname), do: parse_socket(pathname, <<>>)

  defp parse_socket(<<>>, acc), do: acc
  defp parse_socket(<<0, _rest :: binary>>, acc), do: acc
  defp parse_socket(<<char :: binary-size(1), rest :: binary>>, acc) do
    parse_socket(rest, acc <> char)
  end
end
