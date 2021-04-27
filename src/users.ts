type UserId = string;

type Nonce = {
  token: string;
  created: number;
};

type User = {
  password: string;
  nonce: Nonce | null;
};

const users: Map<UserId, User> = new Map();

export const hasUser = async (id: UserId): Promise<boolean> => {
  return users.has(id);
};

export const getUser = async (id: UserId): Promise<User> => {
  const user = users.get(id);
  if (user) return user;
  throw new Error("User doesn't exist");
};

export const setUser = async (id: UserId, data: User): Promise<void> => {
  users.set(id, data);
};

export const updateUser = async (id: UserId, data: Partial<User>): Promise<void> => {
  try {
    users.set(id, { ...(await getUser(id)), ...data });
  } catch (error) {
    throw error;
  }
};
