---
"@x402/extensions": minor
---

Added the `delivery-receipt` extension (`@x402/extensions/delivery-receipt`): a resource server signs, after a successful settle, a receipt binding the settlement (network, transaction, log index, asset, payTo, amount, payer) to the SHA-256 of the served response body. Algorithms are declared (`ml-dsa-65` baseline, `ml-dsa-87`, `ed25519`) and keys are published in a signed key directory. Includes `withDeliveryReceipts` for clients to verify receipts against the payment they sent and the body they received.
