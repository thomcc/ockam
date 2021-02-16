defmodule Ockam.Wire.Base.Tests do
  use ExUnit.Case, async: true

  @address_schema {:struct, [type: :uint, value: :data]}
  @route_schema {:array, @address_schema}
  @message_schema {:struct,
                   [
                     version: :uint,
                     onward_route: @route_schema,
                     return_route: @route_schema,
                     payload: :data
                   ]}

  test "empty message" do
    message = %{version: 1, onward_route: [], return_route: [], payload: ""}
    encoded = :bare.encode(message, @message_schema)
    expected = <<1, 0, 0, 0>>
    assert encoded === expected
  end

  test "message with payload1" do
    message = %{version: 1, onward_route: [], return_route: [], payload: <<100>>}
    encoded = :bare.encode(message, @message_schema)
    expected = <<1, 0, 0, 1, 100>>
    assert encoded === expected
  end

  test "message with payload2" do
    message = %{version: 1, onward_route: [], return_route: [], payload: "hello"}
    encoded = :bare.encode(message, @message_schema)
    expected = <<1, 0, 0, 5, "hello">>
    assert encoded === expected
  end

  test "message with onward route1" do
    message = %{
      version: 1,
      onward_route: [
        %{type: 5, value: <<10, 20, 30>>}
      ],
      return_route: [],
      payload: <<100>>
    }

    encoded = :bare.encode(message, @message_schema)
    expected = <<1, 1, 5, 3, 10, 20, 30, 0, 1, 100>>
    assert encoded === expected
  end

  test "message with onward route2" do
    message = %{
      version: 1,
      onward_route: [
        %{type: 5, value: <<10, 20, 30>>},
        %{type: 5, value: <<10, 20, 30>>}
      ],
      return_route: [],
      payload: <<100>>
    }

    encoded = :bare.encode(message, @message_schema)
    expected = <<1, 2, 5, 3, 10, 20, 30, 5, 3, 10, 20, 30, 0, 1, 100>>
    assert encoded === expected
  end
end
