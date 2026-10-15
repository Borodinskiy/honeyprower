-- Постоянные ключи демо-ловушек из 002_seed.sql (storage.DemoTrapKeys): их
-- открытые ключи прописаны в deploy/agent-configs, иначе центр не расшифрует
-- события демо-агентов. Применяется при каждом старте после сида, поэтому
-- ключи получат и базы, созданные до их появления.
UPDATE traps SET key_id = k.key_id, pub_key = k.pub_key, priv_key = k.priv_key
FROM (VALUES
    ('demo-ssh-banner-token', '426235fef0eb5cc7', 'fd4aace4477ef418a28607d0ca86ee7c022314ba6030d099fd1e8c57413dcd3c', '6f77f425feab05d2263248b5be718f4b29a1a879846f7725fa8be27f8895bca0'),
    ('demo-ftp-token', 'a8936d4c44cc1d8c', 'c693f46070adc608005fa7754d4c663788eda306214be5bc5c268d5938a58a2b', '0651339cf288672dfad8a22dfdef6da2c9ff3d8479fbac708293caf44b3d8027'),
    ('demo-iec104-token', 'beacf504e01ca3c3', 'a356e8c2ecc622bfe5a02db43c7bfac3f0b4bf903e097e3674987e9d59e23e01', '73ab931c56c86bfb25540a0ffced5b79551b2d43a32bf138ac891d4aaca77cb9'),
    ('demo-scada-token', '6017883c2a2b9247', '6c1c0b5ebcf4a2969d42778863b860fb5711c3877b14d4af3e765a05dc797358', 'b535f0eac53cdb42c755ce828488219688d69055e88817f8c8e5b3cc501a679d'),
    ('demo-high-shell-token', '250eb90c8ba75a91', '676ea5738405e3750c1c27b35c81e30a33e0c7d23a8474b5d73f2b8cd8879f47', 'fabf4dcc5054452c6cbfb8531771956b86ac7f22608c577f77929f52a9bbaae0')
) AS k(token, key_id, pub_key, priv_key)
WHERE traps.token = k.token AND traps.priv_key = '';
