class AddChannelKeyToUsers < ActiveRecord::Migration[5.0]
  def change
    add_column :users, :channel_key, :string
  end
end
