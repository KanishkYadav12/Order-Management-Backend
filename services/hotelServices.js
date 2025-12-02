// services/hotelService.js
import Hotel from '../models/hotelModel.js'; // Make sure the model is correct
import { ROLES } from '../utils/constant.js';
import { ClientError, ServerError } from '../utils/errorHandler.js';

export const getHotelByIdService = async (user, hotelId) => {
  try {
    // If the user is a HotelOwner, fetch the hotel using their own hotelId
    const hotelIdToUse = user.role === ROLES.HOTEL_OWNER ? user.hotelId : hotelId;
    const hotel = await Hotel.findById(hotelIdToUse);

    // If no hotel is found, throw a client error
    if (!hotel) {
      throw new ClientError('Hotel not found', 404);
    }

    // HotelOwner can only access their own hotel
    if (user.role === ROLES.HOTEL_OWNER && hotel.ownerId.toString() !== user.id) {
      throw new ClientError('Access denied. You can only view your own hotel.', 403);
    }

    return hotel;
  } catch (error) {
    if(error instanceof ClientError) {
      throw error;
    }
    else {
      throw new ServerError('Error while fetching hotel details');
    }
  }
};


export const updateHotelService = async (user, hotelId, updateData) => {
  try {
    // Fetch the hotel based on the user's role
    const hotelIdToUse = user.role === ROLES.HOTEL_OWNER ? user.hotelId : hotelId;
    const hotel = await Hotel.findById(hotelIdToUse);

    // If no hotel is found, throw a client error
    if (!hotel) {
      throw new ClientError('Hotel not found', 404);
    }

    // SuperAdmin can update any hotel, HotelOwner can only update their own hotel
    if (user.role === ROLES.HOTEL_OWNER && hotel.ownerId.toString() !== user.id) {
      throw new ClientError('Access denied. You can only update your own hotel.', 403);
    }

    // Update the hotel fields with the provided data
    hotel.name = updateData.name || hotel.name;
    hotel.location = updateData.location || hotel.location;
    hotel.logo = updateData.logo || hotel.logo;
    hotel.description = updateData.description || hotel.description;
    hotel.phone = updateData.phone || hotel.phone;
    hotel.description = updateData.description || hotel.description;
    hotel.email = updateData.email || hotel.email;

    // Save the updated hotel
    await hotel.save();

    return hotel;
  } catch (error) {
    if(error instanceof ClientError) {
      throw error;
    }
    else throw new ServerError('Error while updating hotel details');
  }
};


export const deleteHotelService = async (user, hotelId) => {
  try {
    // Fetch the hotel based on the user's role
    const hotelIdToUse = user.role === ROLES.HOTEL_OWNER ? user.hotelId : hotelId;
    const hotel = await Hotel.findById(hotelIdToUse);

    // If no hotel is found, throw a client error
    if (!hotel) {
      throw new ClientError('Hotel not found', 404);
    }

    // SuperAdmin can delete any hotel, HotelOwner can delete only their own hotel
    if (user.role === ROLES.HOTEL_OWNER && hotel.ownerId.toString() !== user.id) {
      throw new ClientError('Access denied. You can only delete your own hotel.', 403);
    }

    // Delete the hotel
    await hotel.remove();

  } catch (error) {
    if(error instanceof ClientError) {
      throw error;
    }
    else
    throw new ServerError('Error while deleting hotel');
  }
};


export const getAllHotelsService = async (user) => {
  try {
    // SuperAdmins are allowed to view all hotels
    if (user.role !== ROLES.SUPER_ADMIN) {
      throw new ClientError('Access denied. Only SuperAdmins can view all hotels.', 403);
    }

    // Fetch all hotels and populate the ownerId field with the owner's name
    const hotels = await Hotel.find().populate('ownerId', 'name');

    return hotels;
  } catch (error) {
    if(error instanceof ClientError) {
      throw error;
    }
    else
    throw new ServerError('Error while fetching hotels',error);
  }
};