#pragma once

#include <cryptofuzz/components.h>
#include <cryptofuzz/module.h>
#include <optional>

namespace cryptofuzz {
namespace module {

class liboqs : public Module {
    public:
        liboqs(void);

        // KEM operations
        std::optional<component::KEM_KeyPair> OpKEM_GenerateKeyPair(operation::KEM_GenerateKeyPair& op) override;
        std::optional<component::KEM_Encapsulated> OpKEM_Encapsulate(operation::KEM_Encapsulate& op) override;
        std::optional<component::KEM_SharedSecret> OpKEM_Decapsulate(operation::KEM_Decapsulate& op) override;

        // PQSign operations
        std::optional<component::PQSign_KeyPair> OpPQSign_GenerateKeyPair(operation::PQSign_GenerateKeyPair& op) override;
        std::optional<component::PQSign_Signature> OpPQSign_Sign(operation::PQSign_Sign& op) override;
        std::optional<bool> OpPQSign_Verify(operation::PQSign_Verify& op) override;
};

} /* namespace module */
} /* namespace cryptofuzz */