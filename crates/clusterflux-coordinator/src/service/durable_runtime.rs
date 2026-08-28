use crate::{
    DurableState, DurableStore, FallibleDurableStore, InMemoryDurableStore, PostgresDurableStore,
};

pub(super) enum RuntimeDurableStore {
    InMemory(Box<InMemoryDurableStore>),
    Postgres(Box<PostgresDurableStore>),
}

impl RuntimeDurableStore {
    pub(super) fn from_database_url(database_url: Option<&str>) -> Result<Self, String> {
        match database_url.map(str::trim).filter(|url| !url.is_empty()) {
            Some(url) => PostgresDurableStore::connect(url)
                .map(Box::new)
                .map(Self::Postgres)
                .map_err(|error| error.to_string()),
            None => Ok(Self::InMemory(Box::default())),
        }
    }

    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::InMemory(_) => "in_memory",
            Self::Postgres(_) => "postgres",
        }
    }
}

impl FallibleDurableStore for RuntimeDurableStore {
    type Error = String;

    fn load_state(&mut self) -> Result<DurableState, Self::Error> {
        match self {
            Self::InMemory(store) => Ok(store.load()),
            Self::Postgres(store) => store.load_state().map_err(|error| error.to_string()),
        }
    }

    fn save_state(&mut self, state: &DurableState) -> Result<(), Self::Error> {
        match self {
            Self::InMemory(store) => {
                store.save(state.clone());
                Ok(())
            }
            Self::Postgres(store) => store.save_state(state).map_err(|error| error.to_string()),
        }
    }
}
