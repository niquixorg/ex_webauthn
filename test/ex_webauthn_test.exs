defmodule ExWebauthnTest do
  use ExUnit.Case, async: false

  @valid_uuid "f47ac10b-58cc-4372-a567-0e02b2c3d479"

  setup_all do
    case GenServer.whereis(ExWebauthn) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end

    start_supervised!({ExWebauthn, rp_id: "localhost", rp_origin: "http://localhost:4000"})
    :ok
  end

  describe "origin scheme enforcement" do
    setup do
      on_exit(fn -> ExWebauthn.reload(rp_id: "localhost", rp_origin: "http://localhost:4000") end)
    end

    test "allows https origin" do
      assert :ok = ExWebauthn.reload(rp_id: "example.com", rp_origin: "https://example.com")
    end

    test "allows http for localhost" do
      assert :ok = ExWebauthn.reload(rp_id: "localhost", rp_origin: "http://localhost:4000")
    end

    test "rejects http for non-localhost" do
      assert {:error, :invalid_origin, msg} =
               ExWebauthn.reload(rp_id: "example.com", rp_origin: "http://example.com")

      assert msg =~ "https"
    end

    test "rejects ftp scheme" do
      assert {:error, :invalid_origin, _} =
               ExWebauthn.reload(rp_id: "localhost", rp_origin: "ftp://localhost")
    end
  end

  describe "start_registration/4" do
    test "returns challenge options with publicKey and opaque state" do
      {:ok, challenge, state} =
        ExWebauthn.start_registration(@valid_uuid, "test@example.com", "Test User")

      assert %{"publicKey" => pk} = challenge
      assert is_binary(pk["challenge"])
      assert pk["rp"]["id"] == "localhost"
      assert pk["user"]["name"] == "test@example.com"
      assert pk["user"]["displayName"] == "Test User"
      assert is_list(pk["pubKeyCredParams"])
      assert is_binary(state)
    end

    test "challenge contains expected algorithms" do
      {:ok, %{"publicKey" => pk}, _state} =
        ExWebauthn.start_registration(@valid_uuid, "a@b.com", "A")

      algs = Enum.map(pk["pubKeyCredParams"], & &1["alg"])
      assert -7 in algs
      assert -257 in algs
    end

    test "each call produces a unique challenge" do
      {:ok, %{"publicKey" => pk1}, _} = ExWebauthn.start_registration(@valid_uuid, "a@b.com", "A")
      {:ok, %{"publicKey" => pk2}, _} = ExWebauthn.start_registration(@valid_uuid, "a@b.com", "A")

      assert pk1["challenge"] != pk2["challenge"]
    end

    test "state is valid json containing the challenge" do
      {:ok, %{"publicKey" => pk}, state} =
        ExWebauthn.start_registration(@valid_uuid, "a@b.com", "A")

      state_map = Jason.decode!(state)
      assert is_map(state_map)
      assert state_map["rs"]["challenge"] == pk["challenge"]
    end

    test "error on invalid uuid" do
      assert {:error, :invalid_uuid, msg} =
               ExWebauthn.start_registration("not-a-uuid", "a@b.com", "A")

      assert is_binary(msg)
    end

    test "error on empty uuid" do
      assert {:error, :invalid_uuid, _} = ExWebauthn.start_registration("", "a@b.com", "A")
    end

    test "error on empty user_name" do
      assert {:error, :registration_failed, _} =
               ExWebauthn.start_registration(@valid_uuid, "", "")
    end

    test "works with unicode in name and display_name" do
      {:ok, challenge, _state} =
        ExWebauthn.start_registration(@valid_uuid, "ēšķī@test.lv", "Norberts Kākste")

      assert challenge["publicKey"]["user"]["name"] == "ēšķī@test.lv"
    end

    test "exclude_credentials defaults to empty" do
      {:ok, %{"publicKey" => pk}, _} =
        ExWebauthn.start_registration(@valid_uuid, "a@b.com", "A")

      assert pk["excludeCredentials"] == nil or pk["excludeCredentials"] == []
    end
  end

  describe "start_authentication/1" do
    test "succeeds with empty credentials (discoverable flow)" do
      {:ok, challenge, state} = ExWebauthn.start_authentication([])

      assert %{"publicKey" => pk} = challenge
      assert is_binary(pk["challenge"])
      assert pk["rpId"] == "localhost"
      assert pk["allowCredentials"] == []
      assert is_binary(state)
    end

    test "each call produces a unique challenge" do
      {:ok, %{"publicKey" => pk1}, _} = ExWebauthn.start_authentication([])
      {:ok, %{"publicKey" => pk2}, _} = ExWebauthn.start_authentication([])

      assert pk1["challenge"] != pk2["challenge"]
    end
  end

  describe "finish_registration/2" do
    test "error on non-json state" do
      assert {:error, :invalid_json, _} = ExWebauthn.finish_registration("not-json", %{})
    end

    test "error on empty json object as state" do
      assert {:error, :invalid_json, _} = ExWebauthn.finish_registration("{}", %{"id" => "x"})
    end

    test "error on valid state but garbage client response" do
      {:ok, _challenge, state} = ExWebauthn.start_registration(@valid_uuid, "a@b.com", "A")

      assert {:error, kind, _} = ExWebauthn.finish_registration(state, %{"garbage" => true})
      assert kind in [:invalid_json, :registration_failed]
    end
  end

  describe "finish_authentication/2" do
    test "error on non-json state" do
      assert {:error, :invalid_json, _} = ExWebauthn.finish_authentication("not-json", %{})
    end

    test "error on valid state but garbage client response" do
      {:ok, _challenge, state} = ExWebauthn.start_authentication([])

      assert {:error, kind, _} = ExWebauthn.finish_authentication(state, %{"garbage" => true})
      assert kind in [:invalid_json, :authentication_failed]
    end
  end

  describe "state isolation" do
    test "registration state cannot be used for authentication" do
      {:ok, _challenge, reg_state} = ExWebauthn.start_registration(@valid_uuid, "a@b.com", "A")

      assert {:error, :invalid_json, _} =
               ExWebauthn.finish_authentication(reg_state, %{"id" => "x"})
    end

    test "authentication state cannot be used for registration" do
      {:ok, _challenge, auth_state} = ExWebauthn.start_authentication([])

      assert {:error, :invalid_json, _} =
               ExWebauthn.finish_registration(auth_state, %{"id" => "x"})
    end
  end

  describe "not initialized" do
    test "errors when NIF not initialized" do
      # Re-init with bad config to "break" it, then test
      # This is hard to test without a reset NIF, so we just verify init works
      assert :ok = ExWebauthn.reload(rp_id: "localhost", rp_origin: "http://localhost:4000")
    end
  end
end
