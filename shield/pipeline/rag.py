import os
from pathlib import Path

from llama_index.core import (
    SimpleDirectoryReader,
    VectorStoreIndex,
    StorageContext,
    load_index_from_storage,
    Settings,
)
from llama_index.embeddings.huggingface import HuggingFaceEmbedding

import config


class RAGEngine:
    def __init__(self):
        Settings.embed_model = HuggingFaceEmbedding(
            model_name=config.EMBEDDING_MODEL
        )
        Settings.llm = None
        self.index = None
        self.query_engine = None

    def build_index(self, force_rebuild=False):
        storage_path = Path(config.VECTOR_STORE_DIR)

        if storage_path.exists() and not force_rebuild:
            try:
                storage_context = StorageContext.from_defaults(
                    persist_dir=str(storage_path)
                )
                self.index = load_index_from_storage(storage_context)
                print(f"Loaded existing index from {storage_path}")
                return
            except Exception:
                pass

        kb_path = Path(config.KNOWLEDGE_BASE_DIR)
        if not kb_path.exists():
            raise FileNotFoundError(f"Knowledge base not found at {kb_path}")

        documents = SimpleDirectoryReader(
            str(kb_path),
            recursive=True,
            required_exts=[".md"],
        ).load_data()

        print(f"Loaded {len(documents)} documents from knowledge base")

        self.index = VectorStoreIndex.from_documents(documents)

        storage_path.mkdir(parents=True, exist_ok=True)
        self.index.storage_context.persist(persist_dir=str(storage_path))
        print(f"Index saved to {storage_path}")

    def retrieve(self, query: str, top_k: int = None) -> list[dict]:
        if self.index is None:
            self.build_index()

        k = top_k or config.RAG_TOP_K

        retriever = self.index.as_retriever(similarity_top_k=k)
        nodes = retriever.retrieve(query)

        results = []
        for node in nodes:
            results.append({
                "text": node.text,
                "score": node.score,
                "source": node.metadata.get("file_name", "unknown"),
            })

        return results


_engine = None


def get_rag_engine() -> RAGEngine:
    global _engine
    if _engine is None:
        _engine = RAGEngine()
        _engine.build_index()
    return _engine


def retrieve_context(query: str, top_k: int = None) -> list[dict]:
    engine = get_rag_engine()
    return engine.retrieve(query, top_k)


if __name__ == "__main__":
    print("Building RAG index from knowledge base...")
    engine = RAGEngine()
    engine.build_index(force_rebuild=True)

    test_queries = [
        "SBI account blocked KYC update link",
        "CBI arrest warrant money laundering call",
        "You have won Rs 50 lakhs lottery",
        "Scan QR code to receive refund",
        "Share your OTP for verification",
    ]

    for query in test_queries:
        print(f"\n{'='*60}")
        print(f"Query: {query}")
        results = engine.retrieve(query, top_k=3)
        for i, r in enumerate(results):
            print(f"  [{i+1}] (score: {r['score']:.3f}) {r['source']}")
            print(f"      {r['text'][:100]}...")
